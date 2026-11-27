package tlsspoof

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/control"
	"golang.org/x/sys/unix"
)

var fragmentID atomic.Uint32

type DesyncSession struct {
	mu         sync.Mutex
	s          *linuxSpoofer
	closed     bool
	opened     bool
	timestamps bool
	mtu        int
}

func newDesyncSession(conn net.Conn) (*DesyncSession, error) {
	raw, err := newRawSpoofer(conn, MethodWrongSequence)
	if err != nil {
		return nil, err
	}
	return &DesyncSession{s: raw.(*linuxSpoofer)}, nil
}
func (d *DesyncSession) Send(p DesyncPacket) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sendLocked(p)
}
func (d *DesyncSession) sendLocked(p DesyncPacket) error {
	if d.closed {
		return net.ErrClosed
	}
	s := d.s
	if !d.opened {
		if err := s.open(); err != nil {
			s.closeRaw()
			return fmt.Errorf("desync: open raw TCP: %w", err)
		}
		if err := unix.SetNonblock(s.rawFD, true); err != nil {
			s.closeRaw()
			return err
		}
		d.opened = true
		if err := control.Conn(s.tcpConn, func(raw uintptr) error {
			info, err := unix.GetsockoptTCPInfo(int(raw), unix.IPPROTO_TCP, unix.TCP_INFO)
			if err != nil {
				return err
			}
			d.timestamps = info.Options&tcpInfoOptionTimestamps != 0
			d.mtu = int(info.Pmtu)
			if d.timestamps {
				ts, err := unix.GetsockoptInt(int(raw), unix.IPPROTO_TCP, unix.TCP_TIMESTAMP)
				if err != nil {
					return err
				}
				s.timestamp = uint32(ts)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if len(p.Payload) == 0 {
		return fmt.Errorf("desync: empty raw payload")
	}
	if len(p.Payload) > 60000 {
		return fmt.Errorf("desync: raw payload exceeds 60000 bytes")
	}
	// Raw IP_HDRINCL does not provide TCP segmentation. Respect path MTU,
	// including worst-case TCP options, on both address families.
	ipSize := 20
	if s.src.Addr().Is6() {
		ipSize = 40
	}
	maxPayload := 1120
	if d.mtu > 0 {
		maxPayload = min(maxPayload, d.mtu-ipSize-60)
	}
	if maxPayload < 1 {
		return fmt.Errorf("desync: route MTU too small for TCP")
	}
	if p.Fake && p.FakeLength == 0 {
		p.FakeLength = len(p.Payload)
	}
	if p.Fragment == 0 && !strings.Contains(p.Fooling, "ipfrag") && len(p.Payload) > maxPayload {
		original := p.Payload
		offset := p.Offset
		for off := 0; off < len(original); off += maxPayload {
			p.Payload = original[off:min(off+maxPayload, len(original))]
			p.Offset = offset + off
			if err := d.sendLocked(p); err != nil {
				return err
			}
		}
		return nil
	}
	info := spoofPacketInfo{seqNum: s.sendNext + uint32(p.Offset), ackNum: s.receiveNext}
	if d.timestamps {
		info.options = make([]byte, 12)
		header.EncodeTSOption(s.timestamp, 0, info.options)
	}
	// Enforce this independently of every configurable fooling method. Even a
	// peer ignoring MD5, ACK or timestamp checks cannot consume fake stream data.
	if p.Fake {
		if p.FakeLength > 60000 || p.Offset < 0 || p.FakeLength < len(p.Payload) || p.Offset > p.FakeLength-len(p.Payload) {
			return fmt.Errorf("desync: fake sequence range would overlap server stream")
		}
		info.seqNum = s.sendNext - uint32(p.FakeLength) + uint32(p.Offset)
	}
	for _, f := range strings.FieldsFunc(p.Fooling, func(r rune) bool { return r == '_' || r == ',' || r == '+' }) {
		switch f {
		case "", "none", "badseq":
		case "badsum":
			info.corrupt = true
		case "badack":
			info.ackNum -= 0x7fffffff
		case "md5":
			info.options = append(info.options, buildMD5SignatureOptions()...)
		case "ts", "badtimestamp":
			if !d.timestamps {
				return fmt.Errorf("desync: timestamp fooling requires negotiated TCP timestamps")
			}
			rewriteTCPOptionTimestamp(info.options, 0)
		case "datanoack", "hopbyhop", "destopt", "ipfrag":
		default:
			return fmt.Errorf("desync: unknown fooling %q", f)
		}
	}
	if len(info.options) > 40 {
		return fmt.Errorf("desync: combined TCP options exceed 40 bytes")
	}
	frame := buildTCPSegment(s.src, s.dst, info, p.Payload)
	s.likeConnection(frame)
	iplen := 20
	if s.src.Addr().Is6() {
		iplen = 40
	}
	if p.TTL > 0 {
		if iplen == 20 {
			frame[8] = byte(p.TTL)
		} else {
			frame[7] = byte(p.TTL)
		}
	}
	tcp := header.TCP(frame[iplen:])
	if p.Window > 0 {
		tcp.SetWindowSize(uint16(p.Window))
	}
	if strings.Contains(p.Fooling, "datanoack") {
		frame[iplen+13] &= ^byte(0x10)
	}
	if p.Urgent {
		frame[iplen+13] |= 0x20
		binary.BigEndian.PutUint16(frame[iplen+18:], uint16(len(p.Payload)))
	}
	tcp.SetChecksum(0)
	applyTCPChecksum(tcp, s.src.Addr(), s.dst.Addr(), p.Payload, info.corrupt)
	if strings.Contains(p.Fooling, "hopbyhop") || strings.Contains(p.Fooling, "destopt") {
		if iplen != 40 {
			return fmt.Errorf("desync: IPv6 extension fooling needs IPv6 destination")
		}
		typ := byte(0)
		if strings.Contains(p.Fooling, "destopt") {
			typ = 60
		}
		ext := []byte{6, 0, 1, 4, 0, 0, 0, 0}
		frame = append(append(append([]byte(nil), frame[:40]...), ext...), frame[40:]...)
		frame[6] = typ
		binary.BigEndian.PutUint16(frame[4:], uint16(len(frame)-40))
	}
	fragment := p.Fragment
	if fragment == 0 && strings.Contains(p.Fooling, "ipfrag") {
		fragment = 48
	}
	if fragment > 0 && d.mtu > 0 {
		overhead := iplen
		if iplen == 40 {
			overhead += 8
		}
		fragment = min(fragment, (d.mtu-overhead)&^7)
	}
	frames, err := fragmentFrames(frame, fragment)
	if err != nil {
		return err
	}
	for _, f := range frames {
		if err = unix.Sendto(s.rawFD, f, 0, s.rawSockAddr); err != nil {
			return fmt.Errorf("desync: raw send: %w", err)
		}
	}
	return nil
}
func (d *DesyncSession) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	return d.s.closeRaw()
}

// Fragment is the fragmentable payload size, rounded down to an 8-byte unit.
func fragmentFrames(frame []byte, size int) ([][]byte, error) {
	if size == 0 {
		return [][]byte{frame}, nil
	}
	size &^= 7
	if size < 8 {
		return nil, fmt.Errorf("desync: ipfrag must be at least 8 bytes")
	}
	ipv6 := frame[0]>>4 == 6
	iplen := 20
	nextAt := 9
	if ipv6 {
		iplen = 40
		nextAt = 6
		// Hop-by-Hop must stay immediately after the IPv6 header (RFC8200).
		if frame[6] == 0 {
			if len(frame) < 48 {
				return nil, fmt.Errorf("desync: truncated Hop-by-Hop header")
			}
			iplen = 40 + 8*(int(frame[41])+1)
			if iplen > len(frame) {
				return nil, fmt.Errorf("desync: truncated Hop-by-Hop header")
			}
			nextAt = 40
		}
	}
	data := frame[iplen:]
	if len(data) <= size {
		return [][]byte{frame}, nil
	}
	firstSize := size
	if ipv6 {
		transport := 0
		proto := frame[nextAt]
		for proto == 60 && transport+8 <= len(data) {
			next := data[transport]
			transport += 8 * (int(data[transport+1]) + 1)
			proto = next
		}
		if proto == 6 && transport+20 <= len(data) {
			headerEnd := transport + int(data[transport+12]>>4)*4
			firstSize = max(firstSize, (headerEnd+7)&^7)
		}
		if firstSize >= len(data) {
			return [][]byte{frame}, nil
		}
	}
	id := fragmentID.Add(1)
	var result [][]byte
	for off := 0; off < len(data); {
		chunk := size
		if off == 0 {
			chunk = firstSize
		}
		n := min(chunk, len(data)-off)
		more := off+n < len(data)
		h := append([]byte(nil), frame[:iplen]...)
		if !ipv6 {
			binary.BigEndian.PutUint16(h[2:], uint16(iplen+n))
			binary.BigEndian.PutUint16(h[4:], uint16(id))
			flags := uint16(off / 8)
			if more {
				flags |= 0x2000
			}
			binary.BigEndian.PutUint16(h[6:], flags)
			h[10] = 0
			h[11] = 0
			ip := header.IPv4(h)
			ip.SetChecksum(^ip.CalculateChecksum())
		} else {
			ext := make([]byte, 8)
			ext[0] = h[nextAt]
			flags := uint16(off)
			if more {
				flags |= 1
			}
			binary.BigEndian.PutUint16(ext[2:], flags)
			binary.BigEndian.PutUint32(ext[4:], id)
			h[nextAt] = 44
			binary.BigEndian.PutUint16(h[4:], uint16(len(h)-40+8+n))
			h = append(h, ext...)
		}
		result = append(result, append(h, data[off:off+n]...))
		off += n
	}
	return result, nil
}
