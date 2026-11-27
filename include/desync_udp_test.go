//go:build linux && integration

package include

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	SJSON "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// A private DNS server resolves a name absent from system DNS while the Box's
// ordinary DNS rules select FakeIP. Both real and fake UDP must use that answer.
func TestDesyncDomainUDPConfiguredResolver(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1"} {
		for _, keep := range []bool{false, true} {
			for _, packet := range []bool{false, true} {
				name := fmt.Sprintf("%s/keep=%t/packet=%t", ip, keep, packet)
				t.Run(name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					target, err := net.ListenPacket("udp", net.JoinHostPort(ip, "0"))
					if err != nil {
						t.Fatal(err)
					}
					defer target.Close()
					_ = target.SetDeadline(time.Now().Add(4 * time.Second))
					dnsSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					var queries atomic.Int64
					resolved := netip.MustParseAddr(ip)
					dnsServer := &mdns.Server{PacketConn: dnsSocket, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
						queries.Add(1)
						reply := new(mdns.Msg)
						reply.SetReply(r)
						for _, q := range r.Question {
							if resolved.Is4() && q.Qtype == mdns.TypeA {
								reply.Answer = append(reply.Answer, &mdns.A{Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.ParseIP(ip)})
							}
							if resolved.Is6() && q.Qtype == mdns.TypeAAAA {
								reply.Answer = append(reply.Answer, &mdns.AAAA{Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: 60}, AAAA: net.ParseIP(ip)})
							}
						}
						_ = w.WriteMsg(reply)
					})}
					go func() { _ = dnsServer.ActivateAndServe() }()
					defer dnsServer.Shutdown()
					_, dnsPort, _ := net.SplitHostPort(dnsSocket.LocalAddr().String())
					dnsPortNumber, _ := strconv.Atoi(dnsPort)
					strategy := "ipv4_only"
					if resolved.Is6() {
						strategy = "ipv6_only"
					}
					config := map[string]any{"log": map[string]any{"disabled": true}, "dns": map[string]any{"servers": []any{map[string]any{"type": "local", "tag": "system-wrong"}, map[string]any{"type": "fakeip", "tag": "wrong-fakeip", "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"}, map[string]any{"type": "udp", "tag": "real-resolver", "server": "127.0.0.1", "server_port": dnsPortNumber, "routing_mark": 65280, "bind_interface": "lo"}}, "final": "system-wrong", "rules": []any{map[string]any{"domain": []string{"udp.desync.test"}, "server": "wrong-fakeip"}}}, "outbounds": []any{map[string]any{"type": "desync", "tag": "dpi", "mode": "none", "udp_mode": "stun", "udp_keep_socket": keep, "udp_repeats": 2, "udp_out_range": "2:2", "udp_ttl": 64, "udp_fake_payload": base64.StdEncoding.EncodeToString([]byte("fake")), "routing_mark": 65280, "bind_interface": "lo", "domain_resolver": map[string]any{"server": "real-resolver", "strategy": strategy}}}}
					content, _ := json.Marshal(config)
					boxCtx := Context(ctx)
					var options option.Options
					if err = SJSON.UnmarshalContext(boxCtx, content, &options); err != nil {
						t.Fatal(err)
					}
					instance, err := box.New(box.Options{Options: options, Context: boxCtx})
					if err != nil {
						t.Fatal(err)
					}
					defer instance.Close()
					if err = instance.Start(); err != nil {
						t.Fatal(err)
					}
					outbound, _ := instance.Outbound().Outbound("dpi")
					_, targetPort, _ := net.SplitHostPort(target.LocalAddr().String())
					logical := M.ParseSocksaddr("udp.desync.test:" + targetPort)
					var send func([]byte) (int, error)
					var receive func([]byte) (int, net.Addr, error)
					var local net.Addr
					if packet {
						conn, err := outbound.ListenPacket(ctx, logical)
						if err != nil {
							t.Fatal(err)
						}
						defer conn.Close()
						_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
						local = conn.LocalAddr()
						sendCount, readCount := 0, 0
						send = func(b []byte) (int, error) {
							sendCount++
							if sendCount == 2 {
								buffer := buf.NewSize(len(b))
								_, _ = buffer.Write(b)
								err := conn.(N.PacketConn).WritePacket(buffer, logical)
								if err != nil {
									return 0, err
								}
								return len(b), nil
							}
							return conn.WriteTo(b, logical)
						}
						receive = func(b []byte) (int, net.Addr, error) {
							readCount++
							if readCount == 2 {
								buffer := buf.NewPacket()
								defer buffer.Release()
								addr, err := conn.(N.PacketConn).ReadPacket(buffer)
								return copy(b, buffer.Bytes()), addr, err
							}
							return conn.ReadFrom(b)
						}
					} else {
						conn, err := outbound.DialContext(ctx, "udp", logical)
						if err != nil {
							t.Fatal(err)
						}
						defer conn.Close()
						_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
						local = conn.LocalAddr()
						send = conn.Write
						receive = func(b []byte) (int, net.Addr, error) { n, err := conn.Read(b); return n, conn.RemoteAddr(), err }
						if remote := M.SocksaddrFromNet(conn.RemoteAddr()); remote.Addr.Unmap() != resolved {
							t.Fatalf("connected via wrong resolver: %s", conn.RemoteAddr())
						}
					}
					setupQueries := queries.Load()
					if setupQueries == 0 {
						t.Fatal("configured resolver not queried")
					}
					// Three real requests, two raw/ordinary fakes only before request number two.
					serverResult := make(chan error, 1)
					go func() {
						var source string
						real, fake := 0, 0
						buffer := make([]byte, 128)
						for range 5 {
							n, addr, err := target.ReadFrom(buffer)
							if err != nil {
								serverResult <- err
								return
							}
							if source == "" {
								source = addr.String()
							}
							if source != addr.String() {
								serverResult <- fmt.Errorf("source tuple changed %s -> %s", source, addr)
								return
							}
							_, sourcePort, _ := net.SplitHostPort(addr.String())
							_, localPort, _ := net.SplitHostPort(local.String())
							if sourcePort != localPort {
								serverResult <- fmt.Errorf("source port %s differs from session %s", sourcePort, localPort)
								return
							}
							if bytes.Equal(buffer[:n], []byte("fake")) {
								fake++
								if real != 1 {
									serverResult <- fmt.Errorf("fake outside inclusive range after %d real", real)
									return
								}
								continue
							}
							real++
							if _, err = target.WriteTo(buffer[:n], addr); err != nil {
								serverResult <- err
								return
							}
						}
						if real != 3 || fake != 2 {
							serverResult <- fmt.Errorf("real=%d fake=%d", real, fake)
							return
						}
						serverResult <- nil
					}()
					request := make([]byte, 20)
					request[1] = 1
					binary.BigEndian.PutUint32(request[4:8], 0x2112a442)
					for i := range 3 {
						request[19] = byte(i)
						if n, err := send(request); err != nil || n != len(request) {
							t.Fatalf("send %d: %d %v", i, n, err)
						}
						reply := make([]byte, 128)
						n, addr, err := receive(reply)
						if err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(reply[:n], request) {
							t.Fatalf("reply changed: %x", reply[:n])
						}
						if packet && addr.String() != logical.String() {
							t.Fatalf("logical reply address lost: %s", addr)
						}
					}
					if err = <-serverResult; err != nil {
						t.Fatal(err)
					}
					if after := queries.Load(); after != setupQueries {
						t.Fatalf("resolved per packet: setup=%d after=%d", setupQueries, after)
					}
				})
			}
		}
	}
}
