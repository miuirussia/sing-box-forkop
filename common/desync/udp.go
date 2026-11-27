package desync

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	"github.com/sagernet/sing-box/common/tlsspoof"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

const maxDestinations = 1024

type udpState struct {
	deadlineMu    sync.Mutex
	writeDeadline time.Time
	closed        chan struct{}
	socket        any
	mu            sync.Mutex
	opts          option.DesyncOptions
	counts        map[string]uint64
	quic          map[string]initialState
	first, last   uint64
	fake          []byte
	ctx           context.Context
	stop          func() bool
	closeOnce     sync.Once
	closeErr      error
	close         func() error
}

func newUDPState(ctx context.Context, o option.DesyncOptions, closeConn func() error) (*udpState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := Validate(o); err != nil {
		return nil, err
	}
	if o.QUICDesync != nil {
		enabled := *o.QUICDesync
		o.QUICDesync = &enabled
	}
	first, last, err := packetRange(o.UDPOutRange)
	if err != nil {
		return nil, err
	}
	fake, _ := base64.StdEncoding.DecodeString(o.UDPFakePayload)
	s := &udpState{ctx: ctx, opts: o, first: first, last: last, fake: fake, counts: make(map[string]uint64), closed: make(chan struct{}), quic: make(map[string]initialState), close: closeConn}
	s.stop = context.AfterFunc(ctx, func() { s.Close() })
	return s, nil
}
func (s *udpState) Close() error {
	s.closeOnce.Do(func() { close(s.closed); s.closeErr = s.close() })
	s.mu.Lock()
	s.mu.Unlock()
	return s.closeErr
}
func (s *udpState) write(b []byte, key string, addr net.Addr, send func([]byte) (int, error), ttl func(int, func([]byte) (int, error), func(func([]byte) (int, error)) error) error) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writeError(); err != nil {
		return 0, err
	}
	if s.opts.UDPMode == "" || s.opts.UDPMode == "none" {
		return send(b)
	}
	count, ok := s.counts[key]
	if !ok && len(s.counts) >= maxDestinations {
		return 0, fmt.Errorf("desync: UDP destination limit (%d) reached", maxDestinations)
	}
	count++
	s.counts[key] = count
	kind := ""
	var metadata adapter.InboundContext
	if (s.opts.UDPMode == "stun" || s.opts.UDPMode == "auto") && sniff.STUNMessage(s.ctx, &metadata, b) == nil {
		kind = "stun"
	}
	if kind == "" && (s.opts.QUICDesync == nil || *s.opts.QUICDesync) && (s.opts.UDPMode == "quic" || s.opts.UDPMode == "auto") && quicInitial(b) {
		// Reuse the sing-box authenticated Initial sniffer. Fragmented CRYPTO is
		// recognized structurally, while metadata is populated when complete.
		_ = sniff.QUICClientHello(s.ctx, &metadata, b)
		kind = "quic"
	}
	wire := b
	var nextState initialState
	if kind != "" && s.opts.UDPLen != 0 {
		var err error
		if kind == "stun" {
			wire, err = padSTUN(b, s.opts.UDPLen)
		} else {
			wire, nextState, err = padQUICInitial(b, s.opts.UDPLen, s.quic[key])
		}
		if err != nil {
			return 0, err
		}
	}
	if kind != "" && count >= s.first && count <= s.last {
		fake := s.fake
		if len(fake) == 0 {
			if kind == "stun" {
				fake = append([]byte(nil), b...)
				fake[0] = 0x01
				fake[1] = 0x11
				_, _ = rand.Read(fake[8:20])
			} else {
				fake = fakeQUICInitial(b)
			}
		}
		repeats := s.opts.UDPRepeats
		if kind == "quic" && s.opts.QUICRepeats > 0 {
			repeats = s.opts.QUICRepeats
		}
		if repeats == 0 {
			repeats = 1
		}
		run := func(write func([]byte) (int, error)) error {
			for i := 0; i < repeats; i++ {
				if err := s.writeError(); err != nil {
					return err
				}
				n, err := write(fake)
				if err != nil {
					return err
				}
				if n != len(fake) {
					return fmt.Errorf("desync: partial fake UDP datagram")
				}
			}

			return nil
		}
		var err error
		if !s.opts.UDPKeepSocket && s.opts.IsExplicit("udp_keep_socket") {
			injector, e := tlsspoof.NewUDPInjector(s.socket, addr)
			if e != nil {
				return 0, e
			}
			err = run(func(payload []byte) (int, error) {
				e := injector.Send(payload, s.opts.UDPTTL)
				if e != nil {
					return 0, e
				}
				return len(payload), nil
			})
			closeErr := injector.Close()
			if err == nil {
				err = closeErr
			}
		} else {
			err = ttl(s.opts.UDPTTL, send, run)
		}
		if err != nil {
			return 0, err
		}
	}

	if err := s.writeError(); err != nil {
		return 0, err
	}
	n, err := send(wire)
	if err != nil {
		return 0, err
	}
	if n != len(wire) {
		return 0, fmt.Errorf("desync: partial UDP datagram")
	}
	if kind == "quic" && s.opts.UDPLen != 0 {
		s.quic[key] = nextState
	}
	return len(b), nil
}

func padSTUN(b []byte, n int) ([]byte, error) {
	if n < 4 || n%4 != 0 {
		return nil, fmt.Errorf("desync: STUN udplen must add at least 4 bytes in 4-byte units")
	}
	size := int(binary.BigEndian.Uint16(b[2:4]))
	if len(b) != 20+size {
		return nil, fmt.Errorf("desync: STUN udplen requires exactly one complete message")
	}
	if len(b)+n > 65507 {
		return nil, fmt.Errorf("desync: padded STUN exceeds UDP size")
	}
	// PADDING follows MESSAGE-INTEGRITY, whose HMAC covers only preceding
	// attributes with the header length adjusted to the integrity attribute.
	// FINGERPRINT remains last and is recomputed without needing credentials.
	fingerprint := -1
	for p := 20; p < len(b); {
		if p+4 > len(b) {
			return nil, fmt.Errorf("desync: truncated STUN attribute")
		}
		typ := binary.BigEndian.Uint16(b[p:])
		l := int(binary.BigEndian.Uint16(b[p+2:]))
		next := p + 4 + ((l + 3) &^ 3)
		if next > len(b) {
			return nil, fmt.Errorf("desync: malformed STUN attribute")
		}
		if typ == 0x8028 {
			if l != 4 || next != len(b) {
				return nil, fmt.Errorf("desync: STUN FINGERPRINT must be last and 4 bytes")
			}
			fingerprint = p
		}
		p = next
	}
	insert := len(b)
	if fingerprint >= 0 {
		insert = fingerprint
	}
	out := append(append([]byte(nil), b[:insert]...), make([]byte, n)...)
	out = append(out, b[insert:]...)
	binary.BigEndian.PutUint16(out[2:4], uint16(size+n))
	binary.BigEndian.PutUint16(out[insert:], 0x0026)
	binary.BigEndian.PutUint16(out[insert+2:], uint16(n-4))
	if fingerprint >= 0 {
		at := fingerprint + n
		binary.BigEndian.PutUint32(out[at+4:], crc32.ChecksumIEEE(out[:at])^0x5354554e)
	}

	return out, nil
}

type UDPConn struct {
	net.Conn
	state *udpState
}

func NewUDPConn(ctx context.Context, conn net.Conn, o option.DesyncOptions) (net.Conn, error) {
	s, err := newUDPState(ctx, o, conn.Close)
	if err != nil {
		return nil, err
	}
	s.socket = conn
	return &UDPConn{conn, s}, nil
}
func (c *UDPConn) Write(b []byte) (int, error) {
	return c.state.write(b, c.RemoteAddr().String(), c.RemoteAddr(), c.Conn.Write, func(ttl int, send func([]byte) (int, error), burst func(func([]byte) (int, error)) error) error {
		return withUDPTTL(c.Conn, c.RemoteAddr(), ttl, send, burst)
	})
}
func (c *UDPConn) Close() error {
	if c.state.stop != nil {
		c.state.stop()
	}
	return c.state.Close()
}
func (c *UDPConn) Upstream() any           { return c.Conn }
func (c *UDPConn) WriterReplaceable() bool { return false }

type PacketConn struct {
	net.PacketConn
	state *udpState
}

func NewPacketConn(ctx context.Context, conn net.PacketConn, o option.DesyncOptions) (net.PacketConn, error) {
	s, err := newUDPState(ctx, o, conn.Close)
	if err != nil {
		return nil, err
	}
	s.socket = conn
	return &PacketConn{conn, s}, nil
}
func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, fmt.Errorf("desync: missing UDP destination")
	}
	return c.state.write(b, udpDestinationKey(addr), addr, func(b []byte) (int, error) { return c.PacketConn.WriteTo(b, addr) }, func(ttl int, send func([]byte) (int, error), burst func(func([]byte) (int, error)) error) error {
		return withUDPTTL(c.PacketConn, addr, ttl, send, burst)
	})
}
func (c *PacketConn) Close() error {
	if c.state.stop != nil {
		c.state.stop()
	}
	return c.state.Close()
}
func (c *PacketConn) Upstream() any           { return c.PacketConn }
func (c *PacketConn) WriterReplaceable() bool { return false }

// PacketConn owns one local socket for its full lifetime. UDPKeepSocket is the
// explicit retention guarantee; both values preserve the source tuple because
// rotating it would break QUIC and STUN request/response association.
var _ net.Conn = (*UDPConn)(nil)
var _ net.PacketConn = (*PacketConn)(nil)

func udpDestinationKey(addr net.Addr) string {
	endpoint := M.AddrPortFromNet(addr)
	if udp, ok := addr.(*net.UDPAddr); ok {
		endpoint = udp.AddrPort()
	}
	if endpoint.IsValid() {
		return M.SocksaddrFrom(endpoint.Addr().Unmap(), endpoint.Port()).String()
	}
	return addr.String()
}

func (s *udpState) writeError() error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	select {
	case <-s.closed:
		return net.ErrClosed
	default:
	}
	s.deadlineMu.Lock()
	deadline := s.writeDeadline
	s.deadlineMu.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	return nil
}
func (s *udpState) setDeadline(t time.Time, set func(time.Time) error) error {
	s.deadlineMu.Lock()
	defer s.deadlineMu.Unlock()
	if err := set(t); err != nil {
		return err
	}
	s.writeDeadline = t
	return nil
}
func (c *UDPConn) SetWriteDeadline(t time.Time) error {
	return c.state.setDeadline(t, c.Conn.SetWriteDeadline)
}
func (c *UDPConn) SetDeadline(t time.Time) error { return c.state.setDeadline(t, c.Conn.SetDeadline) }
func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	return c.state.setDeadline(t, c.PacketConn.SetWriteDeadline)
}
func (c *PacketConn) SetDeadline(t time.Time) error {
	return c.state.setDeadline(t, c.PacketConn.SetDeadline)
}
