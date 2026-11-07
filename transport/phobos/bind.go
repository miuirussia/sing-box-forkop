package phobos

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/sagernet/wireguard-go/conn"
)

const cookie = 0x2112a442

type peerState struct {
	endpoint  conn.Endpoint
	seq       uint16
	timestamp uint32
	ssrc      uint32
	pt        byte
	step      uint16
	lastSend  time.Time
}

// Bind applies obfuscation outside the WireGuard bind, including UDP detours.
type Bind struct {
	conn.Bind
	options Options
	access  sync.Mutex
	peers   map[string]*peerState
	done    chan struct{}
	stopped chan struct{}
}

func NewBind(inner conn.Bind, options Options) *Bind { return &Bind{Bind: inner, options: options} }

func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	b.access.Lock()
	b.peers = make(map[string]*peerState)
	b.done = make(chan struct{})
	b.stopped = make(chan struct{})
	done, stopped := b.done, b.stopped
	b.access.Unlock()
	for i, fn := range fns {
		fns[i] = b.receiver(fn)
	}
	go b.timer(done, stopped)
	return fns, actual, nil
}
func (b *Bind) Close() error {
	// Unblock pending I/O before waiting for the timer or a sender.
	err := b.Bind.Close()
	b.access.Lock()
	done, stopped := b.done, b.stopped
	if done != nil {
		close(done)
		b.done = nil
	}
	b.access.Unlock()
	if stopped != nil {
		<-stopped
	}
	return err
}
func (b *Bind) timer(done <-chan struct{}, stopped chan<- struct{}) {
	defer close(stopped)
	interval := 10 * time.Second
	if b.options.Masking == "MEDIA" {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case now := <-ticker.C:
			b.access.Lock()
			if b.options.Masking == "STUN" || b.options.Masking == "MEDIA" {
				for key, p := range b.peers {
					if now.Sub(p.lastSend) > 180*time.Second {
						delete(b.peers, key)
						continue
					}
					_ = b.Bind.Send([][]byte{stun(1, nil)}, p.endpoint, 0)
				}
			}
			b.access.Unlock()
		}
	}
}
func (b *Bind) state(ep conn.Endpoint) *peerState {
	key := ep.DstToString()
	p := b.peers[key]
	if p != nil {
		p.endpoint = ep
		return p
	}
	// Use one of upstream's H.264 presets when fields are unspecified.
	presets := [][2]uint16{{96, 3000}, {96, 3600}, {96, 3750}, {96, 1500}, {96, 6000}, {97, 3000}, {97, 3600}, {97, 4500}, {97, 9000}, {97, 18000}, {98, 3000}, {98, 3600}, {98, 3750}, {98, 1500}, {98, 6000}, {99, 3000}, {99, 3600}, {100, 3000}, {100, 1500}, {100, 3750}, {102, 3000}, {102, 1500}, {102, 3600}, {104, 3000}, {104, 1500}, {106, 3000}, {106, 3750}, {108, 3000}, {108, 1500}, {110, 3000}, {112, 3000}, {112, 3600}, {114, 3000}, {114, 1500}, {116, 3000}, {118, 3000}, {119, 3000}, {120, 3000}, {122, 3000}, {123, 3000}, {124, 3000}, {125, 3000}, {125, 1500}, {126, 3000}, {127, 3000}, {127, 1500}, {127, 3750}, {96, 1502}, {96, 3003}, {97, 3753}}
	preset := presets[rand.IntN(len(presets))]
	p = &peerState{endpoint: ep, seq: uint16(rand.Uint32()), timestamp: rand.Uint32(), ssrc: b.options.MediaSSRC, pt: b.options.MediaPT, step: preset[1]}
	if p.ssrc == 0 {
		p.ssrc = 1 + rand.Uint32N(0xfffffffe)
	}
	if p.pt == 0 {
		p.pt = byte(preset[0])
	}
	if b.options.MediaClock != 0 {
		p.step = uint16(90000 / b.options.MediaClock)
	}
	b.peers[key] = p
	return p
}
func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	b.access.Lock()
	defer b.access.Unlock()
	if b.done == nil {
		return net.ErrClosed
	}
	p := b.state(ep)
	for _, packet := range bufs {
		if offset < 0 || offset > len(packet) {
			return fmt.Errorf("invalid phobos packet offset")
		}
		packet = packet[offset:]
		payload, err := b.options.encode(packet)
		if err != nil {
			return err
		}
		if packet[0] == 1 && (b.options.Masking == "STUN" || b.options.Masking == "MEDIA") {
			if err = b.Bind.Send([][]byte{stun(1, nil)}, ep, 0); err != nil {
				return err
			}
		}
		switch b.options.Masking {
		case "STUN":
			payload = stun(0x115, payload)
		case "MEDIA":
			header := make([]byte, 12)
			header[0] = 0x80
			header[1] = 0x80 | p.pt
			binary.BigEndian.PutUint16(header[2:], p.seq)
			binary.BigEndian.PutUint32(header[4:], p.timestamp)
			binary.BigEndian.PutUint32(header[8:], p.ssrc)
			p.seq++
			p.timestamp += uint32(p.step)
			payload = append(header, payload...)
		}
		if len(payload) > 65507 {
			return fmt.Errorf("phobos UDP packet exceeds 65507 bytes")
		}
		if err = b.Bind.Send([][]byte{payload}, ep, 0); err != nil {
			return err
		}
		p.lastSend = time.Now()
	}
	return nil
}
func stun(kind uint16, payload []byte) []byte {
	n := 28
	if payload != nil {
		n = 24 + len(payload)
	}
	out := make([]byte, n)
	binary.BigEndian.PutUint16(out, kind)
	binary.BigEndian.PutUint32(out[4:], cookie)
	for i := 8; i < 20; i++ {
		out[i] = byte(rand.Uint32())
	}
	if payload != nil {
		binary.BigEndian.PutUint16(out[20:], 0x13)
		binary.BigEndian.PutUint16(out[22:], uint16(len(payload)))
		copy(out[24:], payload)
	} else {
		binary.BigEndian.PutUint16(out[20:], 0x8028)
		binary.BigEndian.PutUint16(out[22:], 4)
		binary.BigEndian.PutUint32(out[24:], crc32.ChecksumIEEE(out[:20])^0x5354554e)
		binary.BigEndian.PutUint16(out[2:], 8)
	}
	return out
}
func (b *Bind) unwrap(packet []byte, ep conn.Endpoint) []byte {
	masking := b.options.Masking
	if masking == "STUN" || masking == "MEDIA" {
		if len(packet) >= 8 && binary.BigEndian.Uint32(packet[4:]) == cookie {
			if len(packet) < 20 {
				return nil
			}
			kind := binary.BigEndian.Uint16(packet)
			switch kind {
			case 1:
				// Match upstream's fingerprint calculation before setting message length.
				response := stun(1, nil)
				copy(response[8:20], packet[8:20])
				binary.BigEndian.PutUint16(response, 0x101)
				binary.BigEndian.PutUint16(response[2:], 0)
				binary.BigEndian.PutUint32(response[24:], crc32.ChecksumIEEE(response[:20])^0x5354554e)
				binary.BigEndian.PutUint16(response[2:], 8)
				_ = b.Bind.Send([][]byte{response}, ep, 0)
				return nil
			case 0x115:
				if len(packet) < 24 || int(binary.BigEndian.Uint16(packet[2:]))+20 > len(packet) || binary.BigEndian.Uint16(packet[20:]) != 0x13 {
					return nil
				}
				n := int(binary.BigEndian.Uint16(packet[22:]))
				if n > len(packet)-24 {
					return nil
				}
				packet = packet[24 : 24+n]
			default:
				return nil
			}
		} else if masking == "MEDIA" {
			if len(packet) < 16 || packet[0]&0xc0 != 0x80 {
				return nil
			}
			if b.options.MediaPT != 0 && packet[1]&0x7f != b.options.MediaPT {
				return nil
			}
			if b.options.MediaSSRC != 0 && binary.BigEndian.Uint32(packet[8:]) != b.options.MediaSSRC {
				return nil
			}
			packet = packet[12:]
		} else {
			return nil
		}
	}
	decoded, err := b.options.decode(packet)
	if err != nil {
		return nil
	}
	return decoded
}
func (b *Bind) receiver(fn conn.ReceiveFunc) conn.ReceiveFunc {
	// Each receive function owns its scratch space; packets may grow on the wire.
	var scratch [][]byte
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if len(scratch) != len(packets) {
			scratch = make([][]byte, len(packets))
			for i := range scratch {
				scratch[i] = make([]byte, 65535)
			}
		}
		n, err := fn(scratch, sizes, eps)
		for i := 0; i < n; i++ {
			if sizes[i] <= 0 || sizes[i] > len(scratch[i]) {
				sizes[i] = 0
				continue
			}
			decoded := b.unwrap(scratch[i][:sizes[i]], eps[i])
			sizes[i] = 0
			if len(decoded) <= len(packets[i]) {
				sizes[i] = copy(packets[i], decoded)
			}
		}
		return n, err
	}
}
