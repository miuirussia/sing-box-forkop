//go:build linux && integration

package include

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/sys/unix"
)

func TestDesyncProductionRawSocketsUseDialerNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root and network namespace capabilities required")
	}
	for _, command := range []string{"ip", "nft"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skip(command + " required")
		}
	}
	name := fmt.Sprintf("dr%d-%x", os.Getpid(), time.Now().UnixNano())
	run := func(input string, args ...string) {
		t.Helper()
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdin = bytes.NewBufferString(input)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v: %s", args, err, output)
		}
	}
	run("", "ip", "netns", "add", name)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() })
	run("", "ip", "-n", name, "link", "set", "lo", "up")
	run("", "ip", "-n", name, "addr", "add", "10.244.0.1/32", "dev", "lo")
	run("", "ip", "-n", name, "addr", "add", "10.244.0.2/32", "dev", "lo")
	run("", "ip", "-n", name, "-6", "addr", "add", "fd44::1/128", "dev", "lo", "nodad")
	run("", "ip", "-n", name, "-6", "addr", "add", "fd44::2/128", "dev", "lo", "nodad")
	run("table inet review { chain output { type filter hook output priority filter; ip daddr 10.244.0.1 meta mark != 0x08000000 drop; ip6 daddr fd44::1 meta mark != 0x08000000 drop; }; }\n",
		"ip", "netns", "exec", name, "nft", "-f", "-")
	path, _ := json.Marshal("/var/run/netns/" + name)
	base := `"bind_interface":"lo","inet4_bind_address":"10.244.0.2","routing_mark":134217728,"netns":` + string(path)
	for _, tc := range []struct {
		network, target, source, option string
		family                          int
		noPort                          bool
	}{
		{"tcp4", "10.244.0.1", "10.244.0.2", "inet4_bind_address", unix.AF_INET, false},
		{"tcp4", "10.244.0.1", "10.244.0.2", "inet4_bind_address", unix.AF_INET, true},
		{"tcp6", "fd44::1", "fd44::2", "inet6_bind_address", unix.AF_INET6, false},
		{"tcp6", "fd44::1", "fd44::2", "inet6_bind_address", unix.AF_INET6, true},
	} {
		t.Run(fmt.Sprintf("syndata_source_%s/no_port=%t", tc.network, tc.noPort), func(t *testing.T) {
			server, err := listener.ListenNetworkNamespace(context.Background(), name, func() (net.Listener, error) {
				return net.Listen(tc.network, net.JoinHostPort(tc.target, "0"))
			})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			capture, err := listener.ListenNetworkNamespace(context.Background(), name, func() (int, error) {
				return unix.Socket(tc.family, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
			})
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(capture)
			if err = unix.SetsockoptTimeval(capture, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
				t.Fatal(err)
			}
			instance := regressionBox(t, fmt.Sprintf(`{"log":{"disabled":true},"outbounds":[{"type":"desync","tag":"dpi","mode":"split","syndata":"U09VUkNFLUJJTkQtU1lO","bind_address_no_port":%t,"bind_interface":"lo","%s":%q,"routing_mark":134217728,"netns":%s}]}`, tc.noPort, tc.option, tc.source, path))
			out, _ := instance.Outbound().Outbound("dpi")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, err := out.DialContext(ctx, "tcp", M.SocksaddrFromNet(server.Addr()))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			local := M.SocksaddrFromNet(conn.LocalAddr())
			if local.Addr.String() != tc.source {
				t.Fatalf("source = %s, want %s", local, tc.source)
			}
			socket, ok := common.Cast[syscall.Conn](conn)
			if !ok {
				t.Fatal("missing owned socket")
			}
			if err = control.Conn(socket, func(raw uintptr) error {
				mark, err := unix.GetsockoptInt(int(raw), unix.SOL_SOCKET, unix.SO_MARK)
				if err != nil {
					return err
				}
				device, err := unix.GetsockoptString(int(raw), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
				if err == nil && (mark != 134217728 || device != "lo") {
					return fmt.Errorf("routing changed: mark=%d device=%q", mark, device)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 2048)
			for {
				n, from, err := unix.Recvfrom(capture, buffer, 0)
				if err != nil {
					t.Fatalf("fake SYN not received in dialer namespace: %v", err)
				}
				if !bytes.Contains(buffer[:n], []byte("SOURCE-BIND-SYN")) {
					continue
				}
				tcp := buffer[:n]
				source := ""
				if tc.family == unix.AF_INET {
					source = net.IP(buffer[12:16]).String()
					tcp = tcp[int(buffer[0]&15)*4:]
				} else {
					address := from.(*unix.SockaddrInet6).Addr
					source = net.IP(address[:]).String()
				}
				if source != tc.source || int(tcp[0])<<8|int(tcp[1]) != int(local.Port) {
					t.Fatalf("fake SYN tuple differs from real socket: source=%s packet=%x local=%s", source, tcp, local)
				}
				break
			}
			_ = server.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
			peer, err := server.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			_ = peer.SetDeadline(time.Now().Add(time.Second))
			if _, err = conn.Write([]byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")); err != nil {
				t.Fatal(err)
			}
			if err = N.CloseWrite(conn); err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(peer)
			if err != nil || string(body) != "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n" {
				t.Fatalf("stream changed: %q %v", body, err)
			}
		})
	}

	t.Run("tcp_fake", func(t *testing.T) {
		server, err := listener.ListenNetworkNamespace(context.Background(), name, func() (net.Listener, error) { return net.Listen("tcp4", "10.244.0.1:0") })
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		request := []byte("GET / HTTP/1.0\r\nHost: namespace.example\r\n\r\n")
		result := make(chan error, 1)
		go func() {
			conn, err := server.Accept()
			if err != nil {
				result <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			got, err := io.ReadAll(conn)
			if err == nil && !bytes.Equal(got, request) {
				err = fmt.Errorf("raw fake entered stream: %q", got)
			}
			if err == nil {
				_, err = conn.Write([]byte("namespace response"))
			}
			result <- err
		}()
		instance := regressionBox(t, `{"log":{"disabled":true},"outbounds":[{"type":"desync","tag":"dpi","preset":"fake_split","auto_tune":false,`+base+`}]}`)
		out, _ := instance.Outbound().Outbound("dpi")
		conn, err := out.DialContext(context.Background(), "tcp", M.ParseSocksaddr(server.Addr().String()))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err = conn.Write(request); err != nil {
			t.Fatal(err)
		}
		if err = N.CloseWrite(conn); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(conn)
		if err != nil || string(got) != "namespace response" {
			t.Fatalf("response: %q %v", got, err)
		}
		if err = <-result; err != nil {
			t.Fatal(err)
		}
	})
	for _, network := range []string{"dial", "packet"} {
		t.Run("udp_raw_"+network, func(t *testing.T) {
			server, err := listener.ListenNetworkNamespace(context.Background(), name, func() (net.PacketConn, error) { return net.ListenPacket("udp4", "10.244.0.1:0") })
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			_ = server.SetDeadline(time.Now().Add(3 * time.Second))
			fake, _ := json.Marshal(base64.StdEncoding.EncodeToString([]byte("namespace fake")))
			instance := regressionBox(t, `{"log":{"disabled":true},"outbounds":[{"type":"desync","tag":"dpi","mode":"none","syndata":"U09VUkNFLUJJTkQtU1lO","udp_mode":"stun","udp_keep_socket":false,"udp_ttl":64,"udp_fake_payload":`+string(fake)+`,`+base+`}]}`)
			out, _ := instance.Outbound().Outbound("dpi")
			destination := M.ParseSocksaddr(server.LocalAddr().String())
			var send func([]byte) (int, error)
			var receive func([]byte) (int, error)
			var local net.Addr
			if network == "dial" {
				conn, err := out.DialContext(context.Background(), "udp", destination)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				send, receive, local = conn.Write, conn.Read, conn.LocalAddr()
			} else {
				conn, err := out.ListenPacket(context.Background(), destination)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				send = func(p []byte) (int, error) { return conn.WriteTo(p, server.LocalAddr()) }
				receive = func(p []byte) (int, error) { n, _, err := conn.ReadFrom(p); return n, err }
				local = conn.LocalAddr()
			}
			stun := []byte{0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
			if n, err := send(stun); err != nil || n != len(stun) {
				t.Fatalf("send: %d %v", n, err)
			}
			_, port, _ := net.SplitHostPort(local.String())
			seen := map[string]int{}
			var peer net.Addr
			for range 2 {
				buffer := make([]byte, 128)
				n, addr, err := server.ReadFrom(buffer)
				if err != nil {
					t.Fatal(err)
				}
				host, actualPort, _ := net.SplitHostPort(addr.String())
				if host != "10.244.0.2" || actualPort != port {
					t.Fatalf("wrong source tuple: %s, want port %s", addr, port)
				}
				seen[string(buffer[:n])]++
				peer = addr
			}
			if seen["namespace fake"] != 1 || seen[string(stun)] != 1 {
				t.Fatalf("wrong fake/original datagrams: %v", seen)
			}
			if _, err := server.WriteTo([]byte("reply"), peer); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 32)
			if n, err := receive(buffer); err != nil || string(buffer[:n]) != "reply" {
				t.Fatalf("reply lost: %q %v", buffer[:n], err)
			}
		})
	}
}
