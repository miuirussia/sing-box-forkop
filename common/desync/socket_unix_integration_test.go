//go:build (linux || darwin) && integration

package desync

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Observe received IP metadata rather than assuming that both kernels use the
// same socket option for IPv4 packets on a dual-stack socket.
func TestUDPTTLRestoredAfterFailedBurst(t *testing.T) {
	for _, tc := range []struct {
		name, network, server string
		mapped                bool
	}{
		{"ipv4", "udp4", "127.0.0.1:0", false},
		{"dualstack_ipv4", "udp", "127.0.0.1:0", false},
		{"dualstack_ipv6", "udp", "[::1]:0", false},
		{"dualstack_mapped_ipv4", "udp", "127.0.0.1:0", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socket, err := net.ListenUDP(tc.network, &net.UDPAddr{})
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			server, err := net.ListenPacket("udp", tc.server)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			destination := server.LocalAddr().(*net.UDPAddr)
			var receive func([]byte) (int, int, error)
			if destination.AddrPort().Addr().Unmap().Is4() {
				pc := ipv4.NewPacketConn(server)
				if err = pc.SetControlMessage(ipv4.FlagTTL, true); err != nil {
					t.Fatal(err)
				}
				receive = func(b []byte) (int, int, error) {
					n, cm, _, err := pc.ReadFrom(b)
					if cm == nil {
						return n, 0, fmt.Errorf("missing received IPv4 TTL: %v", err)
					}
					return n, cm.TTL, err
				}
			} else {
				pc := ipv6.NewPacketConn(server)
				if err = pc.SetControlMessage(ipv6.FlagHopLimit, true); err != nil {
					t.Fatal(err)
				}
				receive = func(b []byte) (int, int, error) {
					n, cm, _, err := pc.ReadFrom(b)
					if cm == nil {
						return n, 0, fmt.Errorf("missing received IPv6 hop limit: %v", err)
					}
					return n, cm.HopLimit, err
				}
			}
			if tc.mapped {
				destination = &net.UDPAddr{IP: net.ParseIP("::ffff:127.0.0.1"), Port: destination.Port}
			}
			read := func(want string) int {
				t.Helper()
				_ = server.SetReadDeadline(time.Now().Add(time.Second))
				b := make([]byte, 64)
				n, ttl, err := receive(b)
				if err != nil || string(b[:n]) != want {
					t.Fatalf("received %q, want %q: %v", b[:n], want, err)
				}
				return ttl
			}
			if _, err = socket.WriteTo([]byte("baseline"), destination); err != nil {
				t.Fatal(err)
			}
			original := read("baseline")
			if runtime.GOOS == "darwin" && tc.network == "udp" && destination.AddrPort().Addr().Unmap().Is4() {
				called := false
				err = withUDPTTL(socket, destination, 3, nil, func(func([]byte) (int, error)) error { called = true; return nil })
				if err == nil || !strings.Contains(err.Error(), "Darwin") || called {
					t.Fatalf("unsafe mapped TTL was accepted: called=%t error=%v", called, err)
				}
				if _, err = socket.WriteTo([]byte("real"), destination); err != nil {
					t.Fatal(err)
				}
				if got := read("real"); got != original {
					t.Fatalf("rejected mode changed TTL: %d -> %d", original, got)
				}
				return
			}
			failure := errors.New("fake send failed or hit its deadline")
			err = withUDPTTL(socket, destination, 3, func(p []byte) (int, error) { return socket.WriteTo(p, destination) }, func(send func([]byte) (int, error)) error {
				if _, err := send([]byte("fake")); err != nil {
					return err
				}
				return failure
			})
			if !errors.Is(err, failure) {
				t.Fatalf("send error lost: %v", err)
			}
			if got := read("fake"); got != 3 {
				t.Fatalf("fake TTL=%d, want3", got)
			}
			if _, err = socket.WriteTo([]byte("real"), destination); err != nil {
				t.Fatal(err)
			}
			if got := read("real"); got != original {
				t.Fatalf("TTL not restored after error: %d -> %d", original, got)
			}
		})
	}
}
