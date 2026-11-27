//go:build linux && integration

package include

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestDesyncProductionUDPDestinationTTL(t *testing.T) {
	for _, keep := range []bool{true, false} {
		for _, packet := range []bool{true, false} {
			t.Run(fmt.Sprintf("keep=%t/packet=%t", keep, packet), func(t *testing.T) {
				if !keep && os.Geteuid() != 0 {
					t.Skip("raw fake injection requires CAP_NET_RAW")
				}
				instance := regressionBox(t, fmt.Sprintf(`{"log":{"disabled":true},"outbounds":[{"type":"desync","tag":"dpi","mode":"none","udp_mode":"stun","udp_keep_socket":%t,"udp_ttl":3,"udp_out_range":"1:3","udp_fake_payload":"RkFLRQ=="}]}`, keep))
				out, _ := instance.Outbound().Outbound("dpi")
				v4, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer v4.Close()
				v6, err := net.ListenPacket("udp6", "[::1]:0")
				if err != nil {
					t.Fatal(err)
				}
				defer v6.Close()
				p4, p6 := ipv4.NewPacketConn(v4), ipv6.NewPacketConn(v6)
				if err = p4.SetControlMessage(ipv4.FlagTTL, true); err != nil {
					t.Fatal(err)
				}
				if err = p6.SetControlMessage(ipv6.FlagHopLimit, true); err != nil {
					t.Fatal(err)
				}
				var send func([]byte, net.Addr) (int, error)
				if packet {
					conn, err := out.ListenPacket(context.Background(), M.SocksaddrFromNet(v6.LocalAddr()))
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					send = conn.WriteTo
				} else {
					// Connected UDP still uses the actual remote family.
					conn, err := out.DialContext(context.Background(), "udp", M.SocksaddrFromNet(v4.LocalAddr()))
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					send = func(b []byte, _ net.Addr) (int, error) { return conn.Write(b) }
				}
				stun := []byte{0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
				var port int
				for _, family := range []int{6, 4, 6} {
					if !packet {
						family = 4
					}
					target := v4.LocalAddr()
					if family == 6 {
						target = v6.LocalAddr()
					}
					if n, err := send(stun, target); err != nil || n != len(stun) {
						t.Fatalf("send: %d %v", n, err)
					}
					for i := range 2 {
						b := make([]byte, 128)
						var n, ttl int
						var peer net.Addr
						if family == 4 {
							_ = v4.SetReadDeadline(time.Now().Add(time.Second))
							var cm *ipv4.ControlMessage
							n, cm, peer, err = p4.ReadFrom(b)
							if cm != nil {
								ttl = cm.TTL
							}
						} else {
							_ = v6.SetReadDeadline(time.Now().Add(time.Second))
							var cm *ipv6.ControlMessage
							n, cm, peer, err = p6.ReadFrom(b)
							if cm != nil {
								ttl = cm.HopLimit
							}
						}
						if err != nil {
							t.Fatal(err)
						}
						want := stun
						if i == 0 {
							want = []byte("FAKE")
						}
						if !bytes.Equal(b[:n], want) || (i == 0 && ttl != 3) || (i == 1 && ttl <= 3) {
							t.Fatalf("IPv%d packet%d: payload=%x ttl=%d", family, i, b[:n], ttl)
						}
						actualPort := peer.(*net.UDPAddr).Port
						if port != 0 && port != actualPort {
							t.Fatalf("session port changed: %d -> %d", port, actualPort)
						}
						port = actualPort
					}
				}
			})
		}
	}
}
