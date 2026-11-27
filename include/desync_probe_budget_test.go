//go:build integration

package include

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/desync"
)

// Use the real SOCKS listener, router, outbound and TLS client. A client that
// stops before ClientHello completes must not disable another client's retry.
func TestDesyncSOCKSProbeBudgetReleasesStalledClient(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprintf("partial_hello=%t", partial), func(t *testing.T) {
			t.Parallel()
			certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			certificate := certServer.TLS.Certificates[0]
			pool := x509.NewCertPool()
			pool.AddCert(certServer.Certificate())
			certServer.Close()
			target, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			_ = target.(*net.TCPListener).SetDeadline(time.Now().Add(8 * time.Second))
			ready := make(chan error, 1)
			result := make(chan error, 1)
			var applications atomic.Int32
			go func() {
				stalled, err := target.Accept()
				if err != nil {
					ready <- err
					return
				}
				defer stalled.Close()
				_ = stalled.SetDeadline(time.Now().Add(8 * time.Second))
				if partial {
					_, err = io.ReadFull(stalled, make([]byte, 3))
				}
				ready <- err
				if err != nil {
					return
				}
				// Simulate filtering of the next complete ClientHello, before any
				// server response. That connection must be retried by the core.
				first, err := target.Accept()
				if err != nil {
					result <- err
					return
				}
				_ = first.SetDeadline(time.Now().Add(3 * time.Second))
				var header [5]byte
				_, err = io.ReadFull(first, header[:])
				if err == nil {
					_, err = io.CopyN(io.Discard, first, int64(binary.BigEndian.Uint16(header[3:])))
				}
				_ = first.Close()
				if err != nil {
					result <- err
					return
				}
				retry, err := target.Accept()
				if err != nil {
					result <- err
					return
				}
				defer retry.Close()
				_ = retry.SetDeadline(time.Now().Add(3 * time.Second))
				server := tls.Server(retry, &tls.Config{Certificates: []tls.Certificate{certificate}})
				if err = server.Handshake(); err == nil {
					var request [4]byte
					_, err = io.ReadFull(server, request[:])
					if err == nil && string(request[:]) != "once" {
						err = fmt.Errorf("application changed: %q", request)
					}
					if err == nil {
						applications.Add(1)
						_, err = server.Write([]byte("ok"))
					}
				}
				result <- err
			}()
			reservation, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			socksAddress := reservation.Addr().String()
			socksPort := reservation.Addr().(*net.TCPAddr).Port
			_ = reservation.Close()
			instance := regressionBox(t, fmt.Sprintf(`{"log":{"disabled":true},"inbounds":[{"type":"socks","tag":"socks","listen":"127.0.0.1","listen_port":%d}],"outbounds":[{"type":"desync","tag":"dpi","preset":"auto","adaptive":{"timeout":"1s","max_concurrent":1}}]}`, socksPort))
			out, _ := instance.Outbound().Outbound("dpi")
			stats := out.(interface{ DesyncStats() desync.Snapshot }).DesyncStats
			connect := func() net.Conn {
				t.Helper()
				conn, err := net.DialTimeout("tcp4", socksAddress, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = conn.Close() })
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				_, err = conn.Write([]byte{5, 1, 0})
				var greeting [2]byte
				if err == nil {
					_, err = io.ReadFull(conn, greeting[:])
				}
				if err != nil || greeting != [2]byte{5, 0} {
					t.Fatalf("SOCKS greeting: %x %v", greeting, err)
				}
				port := target.Addr().(*net.TCPAddr).Port
				_, err = conn.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)})
				var reply [10]byte
				if err == nil {
					_, err = io.ReadFull(conn, reply[:])
				}
				if err != nil || reply[1] != 0 {
					t.Fatalf("SOCKS connect: %x %v", reply, err)
				}
				return conn
			}
			stalled := connect()
			if partial {
				if _, err = stalled.Write([]byte{22, 3, 1}); err != nil {
					t.Fatal(err)
				}
			}
			if err = <-ready; err != nil {
				t.Fatal(err)
			}
			if stats().Active != 1 {
				t.Fatal("stalled connection did not acquire the probe")
			}
			time.Sleep(1100 * time.Millisecond)
			// Keep the expired client open while the second client needs its slot.
			client := tls.Client(connect(), &tls.Config{ServerName: "example.com", RootCAs: pool})
			defer client.Close()
			if err = client.HandshakeContext(context.Background()); err != nil {
				t.Fatalf("stalled client blocked required TLS retry: %v", err)
			}
			if _, err = client.Write([]byte("once")); err != nil {
				t.Fatal(err)
			}
			var reply [2]byte
			if _, err = io.ReadFull(client, reply[:]); err != nil || string(reply[:]) != "ok" {
				t.Fatalf("response %q: %v", reply, err)
			}
			if err = <-result; err != nil {
				t.Fatal(err)
			}
			if applications.Load() != 1 {
				t.Fatalf("application delivered %d times", applications.Load())
			}
			if snapshot := stats(); snapshot.Active != 0 {
				t.Fatalf("expired/finished permits retained: %d", snapshot.Active)
			}
			_ = stalled.Close()
		})
	}
}
