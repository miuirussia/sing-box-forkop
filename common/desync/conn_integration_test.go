//go:build integration

package desync

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
func TestTLSRealHandshakeAllModes(t *testing.T) {
	for _, mode := range []string{"none", "split", "multi_split", "tlsrec", "fake", "fake_split", "oob", "disorder", "fake_disorder", "multi_disorder", "disoob", "hostfakesplit"} {
		t.Run(mode, func(t *testing.T) {
			if rawMode(mode) && (runtime.GOOS != "linux" || os.Geteuid() != 0) {
				t.Skip("Linux CAP_NET_RAW/CAP_NET_ADMIN required")
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host != "example.com" {
					t.Errorf("Host corrupted: %s", r.Host)
				}
				_, _ = w.Write([]byte("TLS stream intact"))
			}))
			defer server.Close()
			raw, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
			o := option.DesyncOptions{Mode: mode, SplitPos: "sniext+1,midsld,endhost-1", Delay: badoption.Duration(time.Millisecond)}
			if mode == "none" {
				o.Delay = 0
			}
			if mode == "fake_disorder" {
				o.TLSRecFirst = true
			}
			if fakeMode(mode) {
				o.FakeSNI = "fake.example.net"
				o.Repeats = 2
				o.TTL = 64
				o.Fooling = "md5_badack"
			}
			wrapped, err := NewConn(context.Background(), raw, o)
			if err != nil {
				raw.Close()
				t.Fatal(err)
			}
			defer wrapped.Close()
			// Force a real crypto/tls ClientHello across many application Writes.
			client := tls.Client(&chunkingConn{Conn: wrapped, chunk: 13}, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true})
			if err = client.Handshake(); err != nil {
				t.Fatal(err)
			}
			_, err = io.WriteString(client, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
			if err != nil {
				t.Fatal(err)
			}
			reply, err := io.ReadAll(client)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(reply, []byte("TLS stream intact")) {
				t.Fatalf("%q", reply)
			}
		})
	}
}

type chunkingConn struct {
	net.Conn
	chunk int
}

func TestTLSExtendedStrategyHandshake(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options option.DesyncOptions
	}{
		{"independent records", option.DesyncOptions{Mode: "multi_split", TLSRecFirst: true, TLSRecPos: "midsld", SplitPos: "sniext+1,endhost-1"}},
		{"permutation", option.DesyncOptions{Mode: "multi_split", SplitPos: "sni+1,endhost-1", SegmentOrder: "2,1,3"}},
		{"host last", option.DesyncOptions{Mode: "split", SplitPos: "sni,endhost", SegmentOrder: "sni_last"}},
		{"interleaved dynamic fake", option.DesyncOptions{Mode: "fake_split", SplitPos: "sni+1,endhost-1", FakePlacement: "before_between", FakeDelay: badoption.Duration(time.Millisecond), FakeTLSRandom: true, FakeTLSTemplate: "compact", FakeTLSSize: 4096, TTL: 64}},
		{"host decoy across records", option.DesyncOptions{Mode: "hostfakesplit", HostFakeMode: "replace", TLSRecFirst: true, TLSRecPos: "midsld", SplitPos: "midsld", FakeSNI: "decoy.test", Fooling: "none", TTL: 64}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if (rawMode(tc.options.Mode) || tc.options.SegmentOrder != "") && (runtime.GOOS != "linux" || os.Geteuid() != 0) {
				t.Skip("Linux CAP_NET_RAW/CAP_NET_ADMIN required")
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("extended TLS intact"))
			}))
			defer server.Close()
			raw, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
			o, err := option.NormalizeDesyncOptions(tc.options)
			if err != nil {
				t.Fatal(err)
			}
			wrapped, err := NewConn(context.Background(), raw, o)
			if err != nil {
				t.Fatal(err)
			}
			defer wrapped.Close()
			client := tls.Client(&chunkingConn{Conn: wrapped, chunk: 13}, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true})
			if err = client.Handshake(); err != nil {
				t.Fatal(err)
			}
			if _, err = io.WriteString(client, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			reply, err := io.ReadAll(client)
			if err != nil || !bytes.Contains(reply, []byte("extended TLS intact")) {
				t.Fatalf("TLS application stream: %q, %v", reply, err)
			}
		})
	}
}

func (c *chunkingConn) Write(b []byte) (int, error) {
	n := 0
	for len(b) > 0 {
		size := min(c.chunk, len(b))
		w, err := c.Conn.Write(b[:size])
		n += w
		b = b[w:]
		if err != nil {
			return n, err
		}
		if w == 0 {
			return n, io.ErrShortWrite
		}
	}
	return n, nil
}
func TestHTTPRealStreamAllModes(t *testing.T) {
	for _, mode := range []string{"split", "multi_split", "tlsrec", "fake", "fake_split", "disorder", "multi_disorder", "fake_disorder", "oob", "disoob", "hostfakesplit"} {
		t.Run(mode, func(t *testing.T) {
			if rawMode(mode) && (runtime.GOOS != "linux" || os.Geteuid() != 0) {
				t.Skip("raw privileges required")
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			received := make(chan []byte, 1)
			go func() {
				c, err := listener.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
				b, _ := io.ReadAll(c)
				received <- b
			}()
			raw, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
			o := option.DesyncOptions{Mode: mode, SplitPos: "host+1,midsld,endhost-1"}
			if fakeMode(mode) {
				o.FakeHost = "fake.example.net"
				o.TTL = 64
				o.Repeats = 3
				o.Fooling = "badseq_badack_badsum"
			}
			conn, err := NewConn(context.Background(), raw, o)
			if err != nil {
				raw.Close()
				t.Fatal(err)
			}
			defer conn.Close()
			original := []byte("POST /side-effect HTTP/1.1\r\nHost: www.example.com\r\nContent-Length: 5\r\n\r\nabcde")
			for i := 0; i < len(original); i += 3 {
				if _, err = conn.Write(original[i:min(i+3, len(original))]); err != nil {
					t.Fatal(err)
				}
			}
			if err = conn.(*Conn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-received:
				if !bytes.Equal(got, original) {
					t.Fatalf("server stream changed: %q", got)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("server receive timeout")
			}
		})
	}
}

func TestHTTPHostTransformRealRequest(t *testing.T) {
	const body = "body containing Host: untouched.example\r\n"
	requests := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil || !strings.EqualFold(r.Host, "www.example.com:8080") || string(b) != body {
			t.Errorf("request semantics changed: Host=%q body=%q err=%v", r.Host, b, err)
		}
		requests <- r.Host
		_, _ = io.WriteString(w, "HTTP body intact")
	}))
	defer server.Close()
	raw, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	wrapped, err := NewConn(context.Background(), raw, option.DesyncOptions{Mode: "multi_split", SplitPos: "host+1,midsld", HTTPMod: "hcsmix,dcsmix,rmspace"})
	if err != nil {
		t.Fatal(err)
	}
	defer wrapped.Close()
	request := fmt.Sprintf("POST / HTTP/1.1\r\nHost: www.example.com:8080\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	if _, err = io.WriteString(wrapped, request); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(wrapped)
	if err != nil || !bytes.Contains(reply, []byte("HTTP body intact")) {
		t.Fatalf("HTTP response: %q, %v", reply, err)
	}
	if len(requests) != 1 {
		t.Fatalf("server saw %d requests, want one", len(requests))
	}
}
func stunRequest() []byte {
	b := make([]byte, 20)
	b[1] = 1
	b[4] = 0x21
	b[5] = 0x12
	b[6] = 0xa4
	b[7] = 0x42
	for i := 8; i < 20; i++ {
		b[i] = byte(i)
	}
	return b
}
func TestUDPRealDialAndPacketFlows(t *testing.T) {
	for _, dial := range []bool{true, false} {
		t.Run(fmt.Sprint(dial), func(t *testing.T) {
			server, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			_ = server.SetDeadline(time.Now().Add(3 * time.Second))
			o := option.DesyncOptions{Mode: "none", UDPMode: "stun", UDPRepeats: 2, UDPTTL: 64, UDPOutRange: "2:3", UDPKeepSocket: true, UDPFakePayload: base64.StdEncoding.EncodeToString([]byte("FAKE-DATAGRAM"))}
			var send func([]byte) (int, error)
			var closeConn func() error
			if dial {
				c, err := net.Dial("udp4", server.LocalAddr().String())
				if err != nil {
					t.Fatal(err)
				}
				wrapped, err := NewUDPConn(context.Background(), c, o)
				if err != nil {
					c.Close()
					t.Fatal(err)
				}
				send = wrapped.Write
				closeConn = wrapped.Close
			} else {
				c, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				wrapped, err := NewPacketConn(context.Background(), c, o)
				if err != nil {
					c.Close()
					t.Fatal(err)
				}
				send = func(b []byte) (int, error) { return wrapped.WriteTo(b, server.LocalAddr()) }
				closeConn = wrapped.Close
			}
			defer closeConn()
			real := stunRequest()
			for i := 0; i < 4; i++ {
				n, err := send(real)
				if err != nil || n != len(real) {
					t.Fatalf("send %d %v", n, err)
				}
			}
			fakeN, realN := 0, 0
			port := ""
			buf := make([]byte, 2048)
			for i := 0; i < 8; i++ {
				n, addr, err := server.ReadFrom(buf)
				if err != nil {
					t.Fatal(err)
				}
				if port == "" {
					port = addr.String()
				}
				if addr.String() != port {
					t.Fatal("source port changed")
				}
				switch {
				case bytes.Equal(buf[:n], real):
					realN++
				case string(buf[:n]) == "FAKE-DATAGRAM":
					fakeN++
				default:
					t.Fatalf("unexpected %q", buf[:n])
				}
			}
			if fakeN != 4 || realN != 4 {
				t.Fatalf("fake %d real %d", fakeN, realN)
			}
		})
	}
}
func TestUDPRealQUICHandshake(t *testing.T) {
	for _, tc := range []struct {
		name    string
		dial    bool
		version quic.Version
		split   string
		order   string
	}{
		{"packet-v1", false, quic.Version1, "", ""}, {"dial-v1", true, quic.Version1, "", ""},
		{"packet-v2", false, quic.Version2, "", ""}, {"dial-v2", true, quic.Version2, "", ""},
		{"crypto-packet-v1", false, quic.Version1, "1,32", "reverse"}, {"crypto-dial-v1", true, quic.Version1, "1,32", "reverse"},
		{"crypto-packet-v2", false, quic.Version2, "1,32", "reverse"}, {"crypto-dial-v2", true, quic.Version2, "1,32", "reverse"},
		{"sni-packet-v1", false, quic.Version1, "midsld", "sni_last"}, {"sni-dial-v2", true, quic.Version2, "midsld", "sni_last"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			quicConfig := &quic.Config{Versions: []quic.Version{tc.version}}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{testCertificate(t)}, NextProtos: []string{"desync-test"}}, quicConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				c, err := listener.Accept(ctx)
				if err == nil {
					var stream *quic.Stream
					stream, err = c.AcceptStream(ctx)
					if err == nil {
						b := make([]byte, 4)
						_, err = io.ReadFull(stream, b)
						if err == nil && string(b) != "PING" {
							err = fmt.Errorf("changed QUIC payload %q", b)
						}
						if err == nil {
							_, err = stream.Write([]byte("PONG"))
						}
					}
				}
				done <- err
			}()
			o := option.DesyncOptions{Mode: "none", UDPMode: "quic", UDPLen: 32, UDPRepeats: 2, UDPTTL: 64, UDPOutRange: "1:2", UDPKeepSocket: true}
			o.QUICSplitPos, o.QUICOrder = tc.split, tc.order
			clientTLS := &tls.Config{ServerName: "example.com", InsecureSkipVerify: true, NextProtos: []string{"desync-test"}}
			var client *quic.Conn
			if tc.dial {
				raw, err := net.Dial("udp4", listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				c, err := NewUDPConn(ctx, raw, o)
				if err != nil {
					raw.Close()
					t.Fatal(err)
				}
				defer c.Close()
				client, err = quic.DialConn(ctx, c, clientTLS, quicConfig)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				c, err := NewPacketConn(ctx, raw, o)
				if err != nil {
					raw.Close()
					t.Fatal(err)
				}
				defer c.Close()
				client, err = quic.Dial(ctx, c, listener.Addr(), clientTLS, quicConfig)
				if err != nil {
					t.Fatal(err)
				}
			}
			defer client.CloseWithError(0, "")
			stream, err := client.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = stream.Write([]byte("PING")); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, 4)
			if _, err = io.ReadFull(stream, reply); err != nil {
				t.Fatal(err)
			}
			if string(reply) != "PONG" {
				t.Fatal(string(reply))
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestUDPConcurrentCloseCancellation(t *testing.T) {
	raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c, err := NewPacketConn(ctx, raw, option.DesyncOptions{Mode: "none", UDPMode: "stun", UDPOutRange: "1:1"})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_, _ = c.WriteTo(stunRequest(), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
				_ = c.SetWriteDeadline(time.Now().Add(time.Second))
			}
		}()
	}
	cancel()
	_ = c.Close()
	wg.Wait()
}

func TestUDPSTUNBindingWithPadding(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := server.ReadFrom(buf)
			if err != nil {
				done <- err
				return
			}
			if n < 20 || buf[0] != 0 || buf[1] != 1 {
				continue
			}
			if n != 28 {
				done <- fmt.Errorf("STUN padding length %d want28", n)
				return
			}
			reply := append([]byte(nil), buf[:20]...)
			reply[0] = 1
			reply[1] = 1
			reply[2] = 0
			reply[3] = 0
			_, err = server.WriteTo(reply, addr)
			done <- err
			return
		}
	}()
	raw, err := net.Dial("udp4", server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewUDPConn(context.Background(), raw, option.DesyncOptions{Mode: "none", UDPMode: "stun", UDPRepeats: 2, UDPTTL: 64, UDPLen: 8})
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	request := stunRequest()
	n, err := c.Write(request)
	if err != nil || n != len(request) {
		t.Fatalf("%d %v", n, err)
	}
	reply := make([]byte, 100)
	n, err = c.Read(reply)
	if err != nil {
		t.Fatal(err)
	}
	if n != 20 || reply[0] != 1 || reply[1] != 1 || !bytes.Equal(reply[8:20], request[8:20]) {
		t.Fatalf("invalid STUN Binding response %x", reply[:n])
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestUDPEphemeralRawFakePreservesPortAndReplies(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("Linux CAP_NET_RAW required")
	}
	for _, host := range []string{"127.0.0.1", "::1"} {
		for _, dial := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/dial=%v", host, dial), func(t *testing.T) {
				network := "udp4"
				wildcard := "0.0.0.0:0"
				if host == "::1" {
					network = "udp6"
					wildcard = "[::]:0"
				}
				server, err := net.ListenPacket(network, net.JoinHostPort(host, "0"))
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				_ = server.SetDeadline(time.Now().Add(3 * time.Second))
				parsed, err := option.ParseDesyncStrategy("mode=none udp_mode=stun udp_keep_socket=false udp_repeats=2 udp_ttl=64 udp_out_range=2:3 udp_fake_payload=" + base64.StdEncoding.EncodeToString([]byte("EPHEMERAL-FAKE")))
				if err != nil {
					t.Fatal(err)
				}
				o, err := option.NormalizeDesyncOptions(parsed)
				if err != nil {
					t.Fatal(err)
				}
				var send func([]byte) (int, error)
				var read func([]byte) (int, error)
				var closeConn func() error
				var local net.Addr
				if dial {
					raw, err := net.Dial(network, server.LocalAddr().String())
					if err != nil {
						t.Fatal(err)
					}
					c, err := NewUDPConn(context.Background(), raw, o)
					if err != nil {
						raw.Close()
						t.Fatal(err)
					}
					_ = c.SetDeadline(time.Now().Add(3 * time.Second))
					send, read, closeConn, local = c.Write, c.Read, c.Close, c.LocalAddr()
				} else {
					raw, err := net.ListenPacket(network, wildcard)
					if err != nil {
						t.Fatal(err)
					}
					c, err := NewPacketConn(context.Background(), raw, o)
					if err != nil {
						raw.Close()
						t.Fatal(err)
					}
					_ = c.SetDeadline(time.Now().Add(3 * time.Second))
					send = func(b []byte) (int, error) { return c.WriteTo(b, server.LocalAddr()) }
					read = func(b []byte) (int, error) { n, _, err := c.ReadFrom(b); return n, err }
					closeConn, local = c.Close, c.LocalAddr()
				}
				defer closeConn()
				fdsBefore, _ := os.ReadDir("/proc/self/fd")
				real := stunRequest()
				for i := 0; i < 4; i++ {
					if n, err := send(real); err != nil || n != len(real) {
						t.Fatalf("write %d: %d %v", i, n, err)
					}
				}
				fdsAfter, _ := os.ReadDir("/proc/self/fd")
				if len(fdsAfter) > len(fdsBefore) {
					t.Fatalf("ephemeral fake socket leaked: %d -> %d", len(fdsBefore), len(fdsAfter))
				}
				_, localPort, _ := net.SplitHostPort(local.String())
				realN, fakeN := 0, 0
				buf := make([]byte, 2048)
				var peer net.Addr
				for i := 0; i < 8; i++ {
					n, addr, err := server.ReadFrom(buf)
					if err != nil {
						t.Fatal(err)
					}
					peer = addr
					_, sourcePort, _ := net.SplitHostPort(addr.String())
					if sourcePort != localPort {
						t.Fatalf("source port %s != %s", sourcePort, localPort)
					}
					if bytes.Equal(buf[:n], real) {
						realN++
					} else if string(buf[:n]) == "EPHEMERAL-FAKE" {
						fakeN++
					} else {
						t.Fatalf("unexpected %x", buf[:n])
					}
				}
				if realN != 4 || fakeN != 4 {
					t.Fatalf("real=%d fake=%d", realN, fakeN)
				}
				if _, err = server.WriteTo([]byte("REPLY"), peer); err != nil {
					t.Fatal(err)
				}
				n, err := read(buf)
				if err != nil || string(buf[:n]) != "REPLY" {
					t.Fatalf("reply stolen/lost: %q %v", buf[:n], err)
				}
			})
		}
	}
}
