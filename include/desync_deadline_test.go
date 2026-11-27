//go:build integration

package include

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// Use the production outbound, including its connection tracking wrappers. Both
// relay scheduling orders must preserve the caller's response deadline after
// non-replayable bytes have been sent, even beyond the entire retry budget.
func TestDesyncAdaptiveNonReplayableResponseDeadlines(t *testing.T) {
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0, 0, 0)
	handshake := append([]byte{1, 0, 0, byte(len(body))}, body...)
	hello := append([]byte{22, 3, 1, 0, byte(len(handshake))}, handshake...)
	for _, data := range []struct {
		name    string
		request []byte
		prefix  []byte
	}{
		{"http", []byte("GET /slow HTTP/1.1\r\nHost: example.com\r\n\r\n"), nil},
		{"binary", []byte{5, 1, 0}, nil},
		{"application", []byte{23, 3, 3, 0, 3, 1, 2, 3}, nil},
		{"application_after_hello", []byte{23, 3, 3, 0, 3, 1, 2, 3}, hello},
	} {
		for _, readFirst := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/read_first=%t", data.name, readFirst), func(t *testing.T) {
				t.Parallel()
				head := "response"
				if data.name == "http" {
					head = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n"
				}
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				serverDone := make(chan error, 1)
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						serverDone <- err
						return
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
					want := append(append([]byte(nil), data.prefix...), data.request...)
					request := make([]byte, len(want))
					_, err = io.ReadFull(conn, request)
					if err == nil && !bytes.Equal(request, want) {
						err = fmt.Errorf("request changed: %x", request)
					}
					if err == nil {
						time.Sleep(1200 * time.Millisecond)
						_, err = conn.Write([]byte(head))
					}
					if err == nil {
						time.Sleep(50 * time.Millisecond)
						_, err = conn.Write([]byte(" body"))
					}
					serverDone <- err
				}()
				instance := regressionBox(t, `{"log":{"disabled":true},"outbounds":[{"type":"desync","tag":"dpi","preset":"auto","adaptive":{"timeout":"1s"}}]}`)
				out, _ := instance.Outbound().Outbound("dpi")
				conn, err := out.DialContext(context.Background(), "tcp", M.ParseSocksaddr(listener.Addr().String()))
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				// Replace a previously supplied read deadline while Read is pending;
				// sealing replay must restore the latest value, not the old one.
				_ = conn.SetReadDeadline(time.Now().Add(time.Second))
				type result struct {
					data []byte
					err  error
				}
				response := make(chan result, 1)
				read := func() { b, err := io.ReadAll(conn); response <- result{b, err} }
				if readFirst {
					go read()
					time.Sleep(20 * time.Millisecond)
				}
				latest := time.Now().Add(3 * time.Second)
				if readFirst {
					latest = time.Time{} // Explicitly clearing a pending read is preserved too.
				}
				if err = conn.SetReadDeadline(latest); err != nil {
					t.Fatal(err)
				}
				if len(data.prefix) > 0 {
					if _, err = conn.Write(data.prefix); err != nil {
						t.Fatal(err)
					}
					// This complete ClientHello arms a retry read deadline. The
					// following application record must disarm a pending Read too.
					time.Sleep(20 * time.Millisecond)
				}
				if _, err = conn.Write(data.request); err != nil {
					t.Fatal(err)
				}
				if !readFirst {
					go read()
				}
				var got result
				select {
				case got = <-response:
				case <-time.After(4 * time.Second):
					t.Fatal("response did not complete")
				}
				if got.err != nil || string(got.data) != head+" body" {
					t.Fatalf("response: %q %v", got.data, got.err)
				}
				if err = <-serverDone; err != nil {
					t.Fatal(err)
				}
				// No retry may have opened another connection to this application.
				_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Millisecond))
				if extra, err := listener.Accept(); err == nil {
					extra.Close()
					t.Fatal("application connection retried")
				}
			})
		}
	}
}

func TestDesyncAdaptiveSealedReadControls(t *testing.T) {
	for _, action := range []string{"deadline", "close", "cancel"} {
		t.Run(action, func(t *testing.T) {
			t.Parallel()
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			request := []byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
			received := make(chan error, 1)
			release := make(chan struct{})
			defer close(release)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					received <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				_, err = io.ReadFull(conn, make([]byte, len(request)))
				received <- err
				<-release
			}()
			instance := regressionBox(t, `{"log":{"disabled":true},"outbounds":[{"type":"desync","tag":"dpi","preset":"auto","adaptive":{"timeout":"1s"}}]}`)
			out, _ := instance.Outbound().Outbound("dpi")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			conn, err := out.DialContext(ctx, "tcp", M.ParseSocksaddr(listener.Addr().String()))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			done := make(chan error, 1)
			go func() { _, err := conn.Read(make([]byte, 1)); done <- err }()
			if _, err = conn.Write(request); err != nil {
				t.Fatal(err)
			}
			if err = <-received; err != nil {
				t.Fatal(err)
			}
			switch action {
			case "deadline":
				err = conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
			case "close":
				err = conn.Close()
			case "cancel":
				cancel()
			}
			if err != nil {
				t.Fatal(err)
			}
			select {
			case err = <-done:
				if action == "deadline" {
					var timeout net.Error
					if !errors.As(err, &timeout) || !timeout.Timeout() {
						t.Fatalf("caller deadline lost: %v", err)
					}
				} else if err == nil {
					t.Fatal("read survived close/cancellation")
				}
			case <-time.After(time.Second):
				t.Fatal("pending read did not stop")
			}
		})
	}
}
