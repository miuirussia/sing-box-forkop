package phobos

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/wireguard-go/conn"
)

type testBind struct {
	conn.Bind
	access sync.Mutex
	sent   [][]byte
	closed bool
}

func (b *testBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.access.Lock()
	b.closed = false
	b.access.Unlock()
	return nil, 1234, nil
}
func (b *testBind) Close() error {
	b.access.Lock()
	defer b.access.Unlock()
	b.closed = true
	return nil
}
func (b *testBind) Send(bufs [][]byte, _ conn.Endpoint, offset int) error {
	b.access.Lock()
	defer b.access.Unlock()
	if b.closed {
		return net.ErrClosed
	}
	for _, p := range bufs {
		b.sent = append(b.sent, bytes.Clone(p[offset:]))
	}
	return nil
}

type testEndpoint struct{ conn.Endpoint }

func (testEndpoint) DstToString() string { return "127.0.0.1:1234" }
func (testEndpoint) DstIP() netip.Addr   { return netip.MustParseAddr("127.0.0.1") }

func TestBindUpstream(t *testing.T) {
	standard := conn.NewStdNetBind(nil)
	for _, test := range []struct {
		name string
		bind conn.Bind
		want conn.Bind
	}{
		{"standard", standard, standard},
		{"phobos standard", NewBind(standard, Options{}), standard},
		{"nested phobos", NewBind(NewBind(standard, Options{}), Options{}), standard},
		{"phobos detour", NewBind(new(testBind), Options{}), nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := common.Cast[*conn.StdNetBind](test.bind)
			if test.want == nil {
				if ok {
					t.Fatal("non-standard bind reported as a standard bind")
				}
			} else if !ok || got != test.want {
				t.Fatal("underlying standard bind is not discoverable")
			}
		})
	}
}

func TestBindFramingAndLifecycle(t *testing.T) {
	for _, mode := range []string{"STUN", "NONE", "AUTO", "MEDIA"} {
		t.Run(mode, func(t *testing.T) {
			inner := new(testBind)
			b := NewBind(inner, Options{Key: "test", Masking: mode, MaxDummy: 4})
			if _, _, err := b.Open(0); err != nil {
				t.Fatal(err)
			}
			original := []byte{9, 9, 4, 0, 0, 0, 5, 6, 7, 8}
			if err := b.Send([][]byte{original}, testEndpoint{}, 2); err != nil {
				t.Fatal(err)
			}
			if original[2] != 4 || original[3] != 0 {
				t.Fatal("mutated input")
			}
			wire := bytes.Clone(inner.sent[len(inner.sent)-1])
			if got := b.unwrap(wire, testEndpoint{}); !bytes.Equal(got, original[2:]) {
				t.Fatalf("unwrap: %x", got)
			}
			if mode == "MEDIA" {
				first := binary.BigEndian.Uint16(inner.sent[0][2:])
				b.Send([][]byte{original}, testEndpoint{}, 2)
				if binary.BigEndian.Uint16(inner.sent[1][2:]) != first+1 {
					t.Fatal("RTP sequence did not advance")
				}
			}
			if err := b.Close(); err != nil {
				t.Fatal(err)
			}
			if err := b.Send([][]byte{original}, testEndpoint{}, 2); err != net.ErrClosed {
				t.Fatalf("send after close: %v", err)
			}
			if _, _, err := b.Open(0); err != nil {
				t.Fatal(err)
			}
			if len(b.peers) != 0 {
				t.Fatal("peer state survived reopen")
			}
			if err := b.Send([][]byte{original}, testEndpoint{}, 2); err != nil {
				t.Fatal(err)
			}
			b.Close()
		})
	}
}
func TestInvalidFraming(t *testing.T) {
	b := NewBind(new(testBind), Options{Key: "test", Masking: "STUN"})
	for _, packet := range [][]byte{nil, {}, {0, 1}, stun(0x115, []byte{1}), stun(0x101, nil)} {
		if got := b.unwrap(packet, testEndpoint{}); len(got) != 0 {
			t.Fatalf("accepted %x", packet)
		}
	}
	packet := stun(0x115, []byte{1, 2, 3, 4})
	binary.BigEndian.PutUint16(packet[22:], 100)
	if got := b.unwrap(packet, testEndpoint{}); len(got) != 0 {
		t.Fatal("accepted oversized attribute")
	}
}
