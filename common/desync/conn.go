package desync

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/tlsspoof"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

const assemblyTimeout = 250 * time.Millisecond

var poolCounter atomic.Uint64

type Conn struct {
	net.Conn
	ctx                 context.Context
	opts                option.DesyncOptions
	writeMu             sync.Mutex
	buffer              []byte
	timer               *time.Timer
	started             time.Time
	finished            bool
	writeClosed         bool
	sticky              error
	raw                 *tlsspoof.DesyncSession
	closed              chan struct{}
	once                sync.Once
	stopContext         func() bool
	stateMu             sync.Mutex
	writeDeadline       time.Time
	firstFlightDeadline time.Time
	firstFlightFinished bool
	changed             chan struct{}
}

func NewConn(ctx context.Context, conn net.Conn, o option.DesyncOptions) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := Validate(o); err != nil {
		return nil, err
	}

	if err := verifyScale(conn, o.WScale, o.WScaleExplicit); err != nil {
		return nil, err
	}
	if o.WScale != 0 || o.WScaleExplicit {
		if err := restoreScaleBuffer(conn); err != nil {
			return nil, err
		}
	}
	if (o.Mode == "" || o.Mode == "none") && o.HTTPMod == "" {
		return conn, nil
	}
	o.FakeSNIPool = append([]string(nil), o.FakeSNIPool...)
	c := &Conn{Conn: conn, ctx: ctx, opts: o, closed: make(chan struct{}), changed: make(chan struct{})}
	if rawMode(o.Mode) || o.SegmentOrder != "" || o.IPFrag != 0 || o.SeqOvl != 0 || o.WSize != 0 {
		s, err := tlsspoof.NewDesyncSession(conn)
		if err != nil {
			return nil, err
		}
		c.raw = s
	}
	if o.AutoTTL {
		ttl, ok := observedConnectionTTL(conn)
		if ok {
			if o.TTL > 0 {
				ttl = min(ttl, o.TTL)
			}
			c.opts.TTL = ttl
		} else if o.TTL == 0 {
			return nil, fmt.Errorf("desync: autottl has no route observation and no fallback TTL")
		}
	}

	c.stopContext = context.AfterFunc(ctx, func() { c.closeUnderlying() })
	return c, nil
}
func (c *Conn) closeUnderlying() { c.once.Do(func() { close(c.closed); _ = c.Conn.Close() }) }
func (c *Conn) Close() error {
	c.closeUnderlying()
	if c.stopContext != nil {
		c.stopContext()
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.timer != nil {
		c.timer.Stop()
	}
	if c.raw != nil {
		return c.raw.Close()
	}
	return nil
}
func (c *Conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.check(); err != nil {
		return 0, err
	}
	if c.sticky != nil {
		return 0, c.sticky
	}
	if c.writeClosed {
		return 0, net.ErrClosed
	}
	if len(b) == 0 {
		return 0, nil
	}
	if c.finished {
		return c.Conn.Write(b)
	}
	if len(c.buffer)+len(b) > maxFlight {
		err := c.flush(false)
		if err != nil {
			return 0, err
		}
		return c.Conn.Write(b)
	}
	if c.started.IsZero() {
		c.started = time.Now()
		wait := assemblyTimeout
		if deadline := c.effectiveWriteDeadline(); !deadline.IsZero() {
			wait = min(wait, max(0, time.Until(deadline)))
		}
		c.timer = time.AfterFunc(wait, func() {
			c.writeMu.Lock()
			defer c.writeMu.Unlock()
			if !c.finished {
				c.sticky = c.flush(false)
				if c.sticky != nil {
					c.closeUnderlying()
				}
			}
		})
	}
	c.buffer = append(c.buffer, b...)
	complete, err := true, error(nil)
	if c.buffer[0] != 22 || initialTLSRecord(c.buffer) {
		complete, err = flightComplete(c.buffer)
	}
	if err != nil {
		c.sticky = err
		c.closeUnderlying()
		return 0, err
	}
	if !complete {
		return len(b), nil
	}
	if c.timer != nil {
		c.timer.Stop()
	}
	// Bytes accepted by preceding calls are never replayed on a replacement
	// socket. A partial send is terminal; report conservatively for this call.
	if err = c.flush(true); err != nil {
		c.sticky = err
		c.closeUnderlying()
		return 0, err
	}
	return len(b), nil
}
func (c *Conn) flush(transform bool) (err error) {
	if c.finished {
		return c.sticky
	}
	c.finished = true
	defer func() {
		err = errors.Join(err, c.finishFirstFlight())
		c.sticky = err
	}()
	b := c.buffer
	c.buffer = nil
	if c.raw != nil {
		defer func() { err = errors.Join(err, c.raw.Close()) }()
	}
	if len(b) == 0 {
		return nil
	}
	if !transform {
		if err := c.check(); err != nil {
			return err
		}
		return writeAll(c.Conn, b)
	}
	o := c.opts
	if o.HTTPMod != "" {
		b, err = transformHTTP(b, o.HTTPMod)
		if err != nil {
			return err
		}
	}
	if o.Mode == "" || o.Mode == "none" {
		return writeAll(c.Conn, b)
	}
	isTLS := initialTLSRecord(b)
	hp, hostErr := flightHostname(b)
	// Host-relative strategies pass unrelated protocols through unchanged.
	specs := []string{o.SplitPos}
	if isTLS && o.Mode == "tlsrec" && o.TLSRecPos != "" {
		specs = []string{o.TLSRecPos}
	} else if isTLS && o.TLSRecFirst {
		specs = append(specs, o.TLSRecPos)
	}
	for _, spec := range specs {
		for _, position := range strings.Split(spec, ",") {
			position = strings.TrimSpace(position)
			if position != "" && position[0] >= 'a' && position[0] <= 'z' && hostErr != nil {
				return writeAll(c.Conn, b)
			}
		}
	}
	if hostErr != nil && (o.SegmentOrder == "sni_last" || o.HostFakeMode == "replace") {
		return writeAll(c.Conn, b)
	}
	if o.Mode == "tlsrec" && !isTLS {
		if c.raw == nil {
			return writeAll(c.Conn, b)
		}
		o.Mode = "split"
	}
	spec := o.SplitPos
	if spec == "" && (o.Mode == "tlsrec" || o.TLSRecFirst) && isTLS {
		spec = "midsld"
	}
	if isTLS && (o.Mode == "tlsrec" || o.TLSRecFirst) {
		recordSpec := o.TLSRecPos
		if recordSpec == "" {
			recordSpec = spec
		}
		recordCuts, e := positions(b, recordSpec)
		if e != nil {
			return e
		}
		b, err = recordSplit(b, recordCuts)
		if err != nil {
			return err
		}
		hp, hostErr = flightHostname(b)
	}
	var cuts []int
	if o.Mode == "tlsrec" {
		for p := 0; p+5 <= len(b) && b[p] == 22; {
			p += 5 + int(b[p+3])<<8 + int(b[p+4])
			if p < len(b) {
				cuts = append(cuts, p)
			}
		}
	} else {
		cuts, err = positions(b, spec)
		if err != nil {
			if (o.Mode == "fake" || o.Mode == "oob") && o.IPFrag == 0 && o.SeqOvl == 0 && o.WSize == 0 && !o.TLSRecFirst {
				cuts = nil
			} else {
				return err
			}
		}
	}
	replaceHost := o.Mode == "hostfakesplit" && o.HostFakeMode == "replace"
	if replaceHost {
		if hp.start > 0 {
			cuts = append(cuts, hp.start)
		}
		if hp.end < len(b) {
			cuts = append(cuts, hp.end)
		}
		sort.Ints(cuts)
		cuts = slices.Compact(cuts)
	}
	bounds := append(append([]int{0}, cuts...), len(b))
	orderSpec := o.SegmentOrder
	if orderSpec == "" && (strings.Contains(o.Mode, "disorder") || o.Mode == "disoob") {
		orderSpec = "reverse"
	}
	hostStart, hostEnd := -1, -1
	if hostErr == nil {
		hostStart, hostEnd = hp.start, hp.end
	}
	order, err := segmentOrder(orderSpec, bounds, hostStart, hostEnd)
	if err != nil {
		return err
	}
	interleaved := o.FakePlacement == "between" || o.FakePlacement == "before_between"
	if interleaved && len(order) < 2 {
		return fmt.Errorf("desync: interleaved fake placement needs at least two segments")
	}
	var fake []byte
	if fakeMode(o.Mode) && (o.FakePayload != "" || hostErr == nil) {
		sni := o.FakeSNI
		if len(o.FakeSNIPool) > 0 {
			sni = o.FakeSNIPool[(poolCounter.Add(1)-1)%uint64(len(o.FakeSNIPool))]
		}
		if replaceHost {
			name := sni
			if !isTLS {
				name = o.FakeHost
			}
			fake, err = hostDecoy(b, name)
		} else {
			custom, _ := base64.StdEncoding.DecodeString(o.FakePayload)
			fake, err = fakePayload(b, sni, o.FakeHost, custom)
			if err == nil && isTLS {
				fake, err = transformFakeTLS(fake, o.FakeTLSRandom, o.FakeTLSSize, o.FakeTLSTemplate)
			}
		}
		if err != nil {
			return err
		}
	}
	fakeDelay := time.Duration(o.FakeDelay)
	if fakeDelay == 0 && !o.IsExplicit("fake_delay") {
		fakeDelay = time.Duration(o.Delay)
	}
	sendFake := func() error {
		for i := 0; i < max(1, o.Repeats) && len(fake) > 0; i++ {
			if e := c.check(); e != nil {
				return e
			}
			packet := tlsspoof.DesyncPacket{Payload: fake, Fake: !replaceHost, Decoy: replaceHost, Fooling: o.Fooling, TTL: o.TTL, Fragment: o.IPFrag, Window: o.WSize, Urgent: o.Mode == "oob" || o.Mode == "disoob"}
			if e := c.raw.Send(packet); e != nil {
				return e
			}
			if e := c.pause(fakeDelay); e != nil {
				return e
			}
		}
		return nil
	}
	if o.FakePlacement != "between" {
		if err = sendFake(); err != nil {
			return err
		}
	}
	if c.raw != nil {
		// The kernel is queued only the original stream after raw transmission;
		// it retains ACK/retransmit ownership for reordered and repeated bytes.
		sendReal := orderSpec != "" || interleaved || replaceHost || o.IPFrag != 0 || o.SeqOvl != 0 || o.WSize != 0
		if sendReal {
			for step, idx := range order {
				start, end := bounds[idx], bounds[idx+1]
				if o.SeqOvl > 0 && start > 0 {
					start = max(0, start-o.SeqOvl)
				}
				for off := start; off < end; {
					n := min(end-off, 1200)
					if o.IPFrag > 0 {
						n = min(end-off, 60000)
					}
					if err = c.check(); err != nil {
						return err
					}
					if err = c.raw.Send(tlsspoof.DesyncPacket{Payload: b[off : off+n], Offset: off, Fragment: o.IPFrag, Window: o.WSize}); err != nil {
						return err
					}
					off += n
				}
				if err = c.pause(time.Duration(o.Delay)); err != nil {
					return err
				}
				if interleaved && step+1 < len(order) {
					if err = sendFake(); err != nil {
						return err
					}
				}
			}
		}
		if err = c.raw.Close(); err != nil {
			return err
		}
	}
	if o.Mode == "fake" || o.Mode == "oob" {
		return writeAll(c.Conn, b)
	}
	start := 0
	for _, end := range append(cuts, len(b)) {
		if err = c.check(); err != nil {
			return err
		}
		if err = writeAll(c.Conn, b[start:end]); err != nil {
			return err
		}
		start = end
		if end < len(b) {
			if err = c.pause(time.Duration(o.Delay)); err != nil {
				return err
			}
		}
	}
	return nil
}

func initialTLSRecord(b []byte) bool {
	return len(b) > 0 && b[0] == 22 && (len(b) < 2 || b[1] == 3) && (len(b) < 3 || b[2] <= 3)
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return fmt.Errorf("desync: invalid write count")
		}
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
func (c *Conn) check() error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	select {
	case <-c.closed:
		return net.ErrClosed
	default:
	}
	deadline := c.effectiveWriteDeadline()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	return nil
}
func (c *Conn) pause(d time.Duration) error {
	if d <= 0 {
		return c.check()
	}
	end := time.Now().Add(d)
	for {
		if err := c.check(); err != nil {
			return err
		}
		c.stateMu.Lock()
		deadline, changed := minimumDeadline(c.writeDeadline, c.firstFlightDeadline), c.changed
		c.stateMu.Unlock()
		wait := time.Until(end)
		if wait <= 0 {
			return nil
		}
		if !deadline.IsZero() {
			wait = min(wait, time.Until(deadline))
		}
		timer := time.NewTimer(max(wait, 0))
		select {
		case <-timer.C:
		case <-c.ctx.Done():
		case <-c.closed:
		case <-changed:
		}
		timer.Stop()
	}
}
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if err := c.Conn.SetWriteDeadline(minimumDeadline(t, c.firstFlightDeadline)); err != nil {
		return err
	}
	c.writeDeadline = t
	close(c.changed)
	c.changed = make(chan struct{})
	return nil
}
func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.Conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetFirstFlightDeadline bounds buffered assembly and initial segmentation
// independently of the caller's deadlines. Completion restores the caller's
// latest write deadline, including an explicitly cleared one.
func (c *Conn) SetFirstFlightDeadline(t time.Time) error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.firstFlightFinished {
		return nil
	}
	c.firstFlightDeadline = t
	close(c.changed)
	c.changed = make(chan struct{})
	return c.Conn.SetWriteDeadline(minimumDeadline(c.writeDeadline, t))
}

func (c *Conn) effectiveWriteDeadline() time.Time {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return minimumDeadline(c.writeDeadline, c.firstFlightDeadline)
}

func minimumDeadline(a, b time.Time) time.Time {
	if b.IsZero() || (!a.IsZero() && a.Before(b)) {
		return a
	}
	return b
}

func (c *Conn) finishFirstFlight() error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.firstFlightFinished = true
	c.firstFlightDeadline = time.Time{}
	return c.Conn.SetWriteDeadline(c.writeDeadline)
}

func (c *Conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return nil
	}
	if err := c.check(); err != nil {
		return err
	}
	if err := c.flush(false); err != nil {
		c.sticky = err
		c.closeUnderlying()
		return err
	}
	writer, _ := N.UnwrapCountWriter(c.Conn, nil)
	if w, ok := N.UnwrapWriter(writer).(N.WriteCloser); ok {
		if err := w.CloseWrite(); err != nil {
			return err
		}
		c.writeClosed = true
		return nil
	}
	return errors.New("desync: underlying connection does not support CloseWrite")
}
func (c *Conn) Upstream() any           { return c.Conn }
func (c *Conn) ReaderReplaceable() bool { return true }
func (c *Conn) WriterReplaceable() bool {
	// finished is set before flushing. Wait until all sends, raw cleanup and
	// deadline restoration have succeeded before handing the socket to splice.
	if !c.writeMu.TryLock() {
		return false
	}
	defer c.writeMu.Unlock()
	return c.finished && c.sticky == nil && !c.writeClosed && c.check() == nil
}

// Let an already-running sing copy recheck and unwrap after the first flight,
// including a timer flush. Adaptive remains outside this wrapper and owns I/O.
func (c *Conn) NeedHandshakeForWrite() bool { return !c.WriterReplaceable() }
