package desync

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// adaptiveConn never replays HTTP, UDP, TLS application records, early_data or
// bytes following ClientHello. Once any server byte is returned replay is sealed.
type adaptiveConn struct {
	mu                                                               sync.Mutex
	readMu, writeMu                                                  sync.Mutex
	conn                                                             net.Conn
	ctx                                                              context.Context
	cancel                                                           context.CancelFunc
	replacing                                                        bool
	retryCancel                                                      context.CancelFunc
	retryTimer                                                       *time.Timer
	probeTimer                                                       *time.Timer
	probeExpired                                                     bool
	stop                                                             func() bool
	adaptive                                                         *Adaptive
	keys                                                             []string
	destination                                                      M.Socksaddr
	dial                                                             tcpDial
	candidates                                                       []option.DesyncOptions
	index, attempts                                                  int
	deadline, started                                                time.Time
	readAttemptDeadline                                              time.Time
	readDeadline, writeDeadline                                      time.Time
	flight                                                           []byte
	sealed, closed, observed, probe, released                        bool
	readBytes, writeBytes                                            int64
	slowSamples                                                      int
	lastRead, lastWrite                                              time.Time
	sampledWriteBytes                                                int64
	writeClosed, reading, writing, initialWriteDone, initialReadDone bool
}

func (c *adaptiveConn) releaseLocked() {
	if c.probeTimer != nil {
		c.probeTimer.Stop()
		c.probeTimer = nil
	}
	if c.probe && !c.released {
		c.adaptive.release(c.keys[0])
		c.released = true
	}
}

// A permit belongs to the bounded initial probe, not the lifetime of an idle
// TCP connection. Never penalize a strategy for a client that has not finished
// ClientHello or is not reading its response. An unanswered read after a complete
// flight may contribute one timeout, while
// subsequent errors/responses from this expired probe cannot change learning.
func (c *adaptiveConn) expireProbeLocked() {
	if c.closed || c.sealed || time.Now().Before(c.deadline) {
		return
	}
	if !c.observed && c.reading && !c.replacing && !c.writing && c.initialWriteDone && ReplayableClientHello(c.flight) && c.ctx.Err() == nil &&
		(c.readDeadline.IsZero() || time.Now().Before(c.readDeadline)) &&
		(c.writeDeadline.IsZero() || time.Now().Before(c.writeDeadline)) {
		c.adaptive.observe(c.keys, strategyID(c.candidates[c.index]), "initial probe budget exhausted", false, time.Since(c.started))
	}
	c.probeExpired = true
	c.observed = true
	c.sealed = true
	c.flight = nil
	c.releaseLocked()
	// Existing socket deadlines still bound an in-flight first write or TLS
	// response wait. Do not install a timeout on ordinary established traffic.
}
func (c *adaptiveConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		c.expireProbeLocked()
		if c.closed {
			c.mu.Unlock()
			return 0, net.ErrClosed
		}
		conn := c.conn
		_ = conn.SetReadDeadline(c.effectiveReadDeadlineLocked())
		c.reading = true
		c.mu.Unlock()
		start := time.Now()
		n, err := conn.Read(p)
		c.mu.Lock()
		c.expireProbeLocked()
		c.reading = false
		if n > 0 {
			c.initialReadDone = true
			c.readBytes += int64(n)
			if !c.observed && !c.closed && c.ctx.Err() == nil {
				reason, success := "server response", true
				if len(c.flight) > 0 && p[0] == 21 {
					reason, success = "TLS alert", false
				}
				c.adaptive.observe(c.keys, strategyID(c.candidates[c.index]), reason, success, time.Since(c.started))
				c.observed = true
			}
			c.sealed = true
			c.flight = nil
			c.releaseLocked()
			_ = conn.SetReadDeadline(c.readDeadline)
			if !c.writing {
				c.finishInitialWriteLocked()
			}
			elapsed := time.Since(start)
			if elapsed > 2*time.Second && n < 1024 && c.writeBytes > c.sampledWriteBytes && time.Since(c.lastWrite) < 10*time.Second {
				c.slowSamples++
			} else {
				c.slowSamples = 0
			}
			if c.slowSamples == 3 && !c.probeExpired && !c.closed && c.ctx.Err() == nil {
				c.adaptive.observe(c.keys, strategyID(c.candidates[c.index]), "three active slow-read observations", false, elapsed)
			}
			c.lastRead = time.Now()
			c.sampledWriteBytes = c.writeBytes
			c.mu.Unlock()
			return n, err
		}
		if err == nil {
			c.mu.Unlock()
			return n, nil
		}
		if c.sealed {
			if !c.observed && !c.closed && c.ctx.Err() == nil {
				c.adaptive.observe(c.keys, strategyID(c.candidates[c.index]), "early read: "+err.Error(), false, time.Since(c.started))
				c.observed = true
			}
			if !errors.Is(err, io.EOF) && !c.probeExpired && !c.closed && c.ctx.Err() == nil && c.readBytes > 0 {
				var timeout net.Error
				if errors.As(err, &timeout) && timeout.Timeout() {
					if c.writeBytes > c.sampledWriteBytes && time.Since(c.lastWrite) < 10*time.Second {
						c.slowSamples++
					} else {
						c.slowSamples = 0
					}
					if c.slowSamples == 3 {
						c.adaptive.observe(c.keys, strategyID(c.candidates[c.index]), "three active stalled-read observations", false, 0)
					}
				} else {
					c.adaptive.observe(c.keys, strategyID(c.candidates[c.index]), "stream: "+err.Error(), false, 0)
				}
			}
			c.mu.Unlock()
			return n, err
		}
		c.mu.Unlock()
		// Serialize the replay decision against new application writes and close.
		c.writeMu.Lock()
		c.mu.Lock()
		c.expireProbeLocked()
		eligible := !c.closed && !c.sealed && ReplayableClientHello(c.flight) && c.index+1 < c.attempts && c.index+1 < len(c.candidates) && time.Now().Before(c.deadline) && c.ctx.Err() == nil && (c.readDeadline.IsZero() || time.Now().Before(c.readDeadline))
		if !c.observed && !c.closed && c.ctx.Err() == nil {
			c.adaptive.observe(c.keys, strategyID(c.candidates[c.index]), "early read: "+err.Error(), false, time.Since(c.started))
			c.observed = true
		}
		if !eligible {
			c.sealed = true
			c.flight = nil
			c.releaseLocked()
			c.mu.Unlock()
			c.writeMu.Unlock()
			return 0, err
		}
		old := c.conn
		c.replacing = true
		c.index++
		opts := c.candidates[c.index]
		flight := append([]byte(nil), c.flight...)
		c.mu.Unlock()
		_ = old.Close()
		trial, cancel := context.WithDeadline(c.ctx, c.deadline)
		c.mu.Lock()
		c.retryCancel = cancel
		c.updateRetryDeadlineLocked()
		c.mu.Unlock()
		replacement, dialErr := c.dial(trial, c.ctx, c.destination, opts)
		cancel()
		c.mu.Lock()
		c.expireProbeLocked()
		c.retryCancel = nil
		if c.retryTimer != nil {
			c.retryTimer.Stop()
			c.retryTimer = nil
		}
		if dialErr != nil && ((!c.readDeadline.IsZero() && !time.Now().Before(c.readDeadline)) || (!c.writeDeadline.IsZero() && !time.Now().Before(c.writeDeadline))) {
			dialErr = os.ErrDeadlineExceeded
		}
		c.replacing = false
		if c.closed {
			if replacement != nil {
				_ = replacement.Close()
			}
			c.mu.Unlock()
			c.writeMu.Unlock()
			return 0, net.ErrClosed
		}
		if dialErr == nil {
			c.conn = replacement
			c.initialWriteDone = false
			c.writing = true
			c.readAttemptDeadline = time.Time{}
			dialErr = c.updateReadDeadlineLocked()
			if dialErr == nil {
				dialErr = c.prepareFirstFlightLocked()
			}
		}
		c.observed = c.probeExpired
		c.mu.Unlock()
		if dialErr == nil {
			_, dialErr = writeAll(replacement, flight)
			c.mu.Lock()
			c.writing = false
			if !c.closed {
				c.finishInitialWriteLocked()
			}
			c.mu.Unlock()
		}
		c.writeMu.Unlock()
		if dialErr != nil {
			c.mu.Lock()
			c.expireProbeLocked()
			if !c.observed && !c.probeExpired && !c.closed && c.ctx.Err() == nil {
				c.adaptive.observe(c.keys, strategyID(opts), "retry: "+dialErr.Error(), false, 0)
			}
			c.observed = true
			c.sealed = true
			c.flight = nil
			c.releaseLocked()
			c.mu.Unlock()
			if replacement != nil {
				_ = replacement.Close()
			}
			return 0, dialErr
		}
	}
}
func earlierDeadline(a, b time.Time) time.Time {
	if b.IsZero() || (!a.IsZero() && a.Before(b)) {
		return a
	}
	return b
}
func writeAll(c net.Conn, p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := c.Write(p)
		total += n
		p = p[n:]
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
func (c *adaptiveConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	c.expireProbeLocked()
	if c.closed || c.writeClosed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	conn := c.conn
	c.writing = true
	if !c.initialWriteDone {
		if err := conn.SetWriteDeadline(c.effectiveWriteDeadlineLocked()); err != nil {
			c.writing = false
			c.mu.Unlock()
			return 0, err
		}
	}
	if !c.sealed {
		if len(c.flight)+len(p) > c.adaptive.options.Adaptive.MaxBuffer {
			c.sealed = true
			c.flight = nil
			c.releaseLocked()
		} else {
			c.flight = append(c.flight, p...)
			if !possibleClientHello(c.flight) {
				c.sealed = true
				c.flight = nil
				c.releaseLocked()
			}
		}
	}
	if !c.initialReadDone {
		// A concurrent Read may already be waiting. Arm a retry timeout only
		// for a complete safe ClientHello, or restore the latest caller deadline
		// immediately when this Write makes replay impossible.
		if err := c.updateReadDeadlineLocked(); err != nil {
			c.writing = false
			c.sealed = true
			c.flight = nil
			c.releaseLocked()
			c.mu.Unlock()
			return 0, err
		}
	}
	c.mu.Unlock()
	n, err := conn.Write(p)
	c.mu.Lock()
	c.expireProbeLocked()
	c.writing = false
	if !c.initialWriteDone {
		c.finishInitialWriteLocked()
	}
	c.writeBytes += int64(n)
	if n > 0 {
		c.lastWrite = time.Now()
	}
	if n != len(p) || err != nil {
		c.sealed = true
		c.flight = nil
		c.releaseLocked()
		_ = conn.SetReadDeadline(c.effectiveReadDeadlineLocked())
		if !c.observed && !c.closed && c.ctx.Err() == nil && err != nil {
			c.adaptive.observe(c.keys, strategyID(c.candidates[c.index]), "write: "+err.Error(), false, 0)
			c.observed = true
		}
	}
	c.mu.Unlock()
	return n, err
}

func (c *adaptiveConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	c.expireProbeLocked()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	if c.writeClosed {
		c.mu.Unlock()
		return nil
	}
	// FIN ends the replayable flight. Preserve the socket and context for the
	// response; a subsequent read error must not reopen and replay after FIN.
	c.sealed = true
	c.flight = nil
	c.releaseLocked()
	_ = c.conn.SetReadDeadline(c.effectiveReadDeadlineLocked())
	c.writing = true
	conn := c.conn
	c.mu.Unlock()
	writer, _ := N.UnwrapCountWriter(conn, nil)
	closer, ok := N.UnwrapWriter(writer).(N.WriteCloser)
	var err error
	if !ok {
		err = errors.New("desync: underlying connection does not support CloseWrite")
	} else {
		err = closer.CloseWrite()
	}
	c.mu.Lock()
	c.writing = false
	if err == nil {
		c.writeClosed = true
		c.finishInitialWriteLocked()
	}
	c.mu.Unlock()
	return err
}
func (c *adaptiveConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	if c.retryTimer != nil {
		c.retryTimer.Stop()
		c.retryTimer = nil
	}
	c.flight = nil
	c.releaseLocked()
	conn := c.conn
	stop := c.stop
	cancel := c.cancel
	c.mu.Unlock()
	if stop != nil {
		stop()
	}
	if cancel != nil {
		cancel()
	}
	return conn.Close()
}
func (c *adaptiveConn) LocalAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.LocalAddr()
}
func (c *adaptiveConn) RemoteAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.RemoteAddr()
}
func (c *adaptiveConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireProbeLocked()
	if c.closed {
		return net.ErrClosed
	}
	c.readDeadline = t
	c.writeDeadline = t
	if c.replacing {
		c.updateRetryDeadlineLocked()
		return nil
	}
	return errors.Join(c.conn.SetReadDeadline(c.effectiveReadDeadlineLocked()), c.conn.SetWriteDeadline(c.effectiveWriteDeadlineLocked()))
}
func (c *adaptiveConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireProbeLocked()
	if c.closed {
		return net.ErrClosed
	}
	c.readDeadline = t
	if c.replacing {
		c.updateRetryDeadlineLocked()
		return nil
	}
	return c.conn.SetReadDeadline(c.effectiveReadDeadlineLocked())
}
func (c *adaptiveConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireProbeLocked()
	if c.closed {
		return net.ErrClosed
	}
	c.writeDeadline = t
	if c.replacing {
		c.updateRetryDeadlineLocked()
		return nil
	}
	return c.conn.SetWriteDeadline(c.effectiveWriteDeadlineLocked())
}

type firstFlightDeadlineSetter interface{ SetFirstFlightDeadline(time.Time) error }

func (c *adaptiveConn) prepareFirstFlightLocked() error {
	if limiter, ok := common.Cast[firstFlightDeadlineSetter](c.conn); ok {
		if err := limiter.SetFirstFlightDeadline(c.deadline); err != nil {
			return err
		}
	}
	return c.conn.SetWriteDeadline(c.effectiveWriteDeadlineLocked())
}

func (c *adaptiveConn) effectiveWriteDeadlineLocked() time.Time {
	if !c.initialWriteDone {
		return earlierDeadline(c.writeDeadline, c.deadline)
	}
	return c.writeDeadline
}

func (c *adaptiveConn) effectiveReadDeadlineLocked() time.Time {
	if !c.initialReadDone && !c.sealed && !c.readAttemptDeadline.IsZero() {
		return earlierDeadline(c.readDeadline, earlierDeadline(c.deadline, c.readAttemptDeadline))
	}
	return c.readDeadline
}

func (c *adaptiveConn) updateReadDeadlineLocked() error {
	if !c.sealed && c.readAttemptDeadline.IsZero() && ReplayableClientHello(c.flight) {
		c.readAttemptDeadline = time.Now().Add(time.Duration(c.adaptive.options.Adaptive.Timeout) / time.Duration(c.attempts))
	}
	return c.conn.SetReadDeadline(c.effectiveReadDeadlineLocked())
}

func (c *adaptiveConn) finishInitialWriteLocked() {
	if !c.sealed && !c.initialReadDone && !ReplayableClientHello(c.flight) {
		// An assembly timeout may flush a partial ClientHello unchanged. Later
		// fragments still belong to the same bounded logical initial flight.
		_ = c.conn.SetWriteDeadline(c.effectiveWriteDeadlineLocked())
		return
	}
	wasDone := c.initialWriteDone
	c.initialWriteDone = true
	// A buffered engine owns its cap until its asynchronous flush finishes.
	// Only a server response can finish that phase earlier.
	if limiter, buffered := common.Cast[firstFlightDeadlineSetter](c.conn); buffered {
		if c.initialReadDone {
			_ = limiter.SetFirstFlightDeadline(time.Time{})
		}
	}
	if !wasDone {
		_ = c.conn.SetWriteDeadline(c.writeDeadline)
	}
}

func possibleClientHello(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	if data[0] != 22 {
		return false
	}
	for len(data) > 0 {
		if len(data) < 5 {
			return true
		}
		if data[0] != 22 || data[1] != 3 || data[2] > 3 {
			return false
		}
		n := int(binary.BigEndian.Uint16(data[3:5]))
		if n == 0 || n > 18432 {
			return false
		}
		if len(data) < 5+n {
			return true
		}
		data = data[5+n:]
	}
	return true
}

// ReplayableClientHello validates the complete record and handshake boundaries,
// variable vectors and extensions, and excludes TLS 1.3 0-RTT offers explicitly.
func ReplayableClientHello(data []byte) bool {
	if len(data) == 0 || !possibleClientHello(data) {
		return false
	}
	var hello []byte
	for len(data) > 0 {
		if len(data) < 5 {
			return false
		}
		n := int(binary.BigEndian.Uint16(data[3:5]))
		if len(data) < 5+n {
			return false
		}
		hello = append(hello, data[5:5+n]...)
		data = data[5+n:]
	}
	if len(hello) < 4 || hello[0] != 1 {
		return false
	}
	length := int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3])
	if length != len(hello)-4 || length < 41 {
		return false
	}
	p := hello[4:]
	if p[0] != 3 || p[1] > 3 {
		return false
	}
	p = p[34:]
	if len(p) < 1 {
		return false
	}
	n := int(p[0])
	if n > 32 || len(p) < 1+n+2 {
		return false
	}
	p = p[1+n:]
	n = int(binary.BigEndian.Uint16(p))
	if n < 2 || n%2 != 0 || len(p) < 2+n+1 {
		return false
	}
	p = p[2+n:]
	n = int(p[0])
	if n < 1 || len(p) < 1+n {
		return false
	}
	p = p[1+n:]
	if len(p) == 0 {
		return true
	}
	if len(p) < 2 {
		return false
	}
	n = int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if n != len(p) {
		return false
	}
	seen := map[uint16]bool{}
	for len(p) > 0 {
		if len(p) < 4 {
			return false
		}
		kind := binary.BigEndian.Uint16(p)
		size := int(binary.BigEndian.Uint16(p[2:]))
		if kind == 42 || seen[kind] || len(p) < 4+size {
			return false
		}
		seen[kind] = true
		p = p[4+size:]
	}
	return true
}

// Deadline changes must also interrupt a replacement dial that is currently
// standing in for Read/Write on the retired socket. The total budget is separate.
func (c *adaptiveConn) updateRetryDeadlineLocked() {
	if c.retryTimer != nil {
		c.retryTimer.Stop()
		c.retryTimer = nil
	}
	if c.retryCancel == nil {
		return
	}
	deadline := c.readDeadline
	if !c.writeDeadline.IsZero() && (deadline.IsZero() || c.writeDeadline.Before(deadline)) {
		deadline = c.writeDeadline
	}
	if !deadline.IsZero() {
		cancel := c.retryCancel
		c.retryTimer = time.AfterFunc(time.Until(deadline), cancel)
	}
}
