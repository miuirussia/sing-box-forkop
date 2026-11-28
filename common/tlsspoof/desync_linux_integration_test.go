//go:build linux && integration

package tlsspoof

import (
	"bytes"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// Raw disorder must be accepted by TCP, not merely visible in capture while
// only the later ordinary fallback delivers all bytes.
func TestDesyncRawRealDeliveredBeforeKernelWrite(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("CAP_NET_RAW/CAP_NET_ADMIN required")
	}
	for attempt := 0; attempt < 12; attempt++ {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		received := make(chan []byte, 1)
		go func() {
			c, err := listener.Accept()
			if err != nil {
				received <- nil
				return
			}
			defer c.Close()
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			b := make([]byte, 12)
			n, _ := io.ReadFull(c, b)
			received <- b[:n]
		}()
		raw, err := net.Dial("tcp4", listener.Addr().String())
		if err != nil {
			listener.Close()
			t.Fatal(err)
		}
		session, err := NewDesyncSession(raw)
		if err != nil {
			raw.Close()
			listener.Close()
			t.Fatal(err)
		}
		payload := []byte("RAW-REAL-TCP")
		if err = session.Send(DesyncPacket{Payload: payload[4:], Offset: 4}); err == nil {
			err = session.Send(DesyncPacket{Payload: payload[:4]})
		}
		if err != nil {
			session.Close()
			raw.Close()
			listener.Close()
			t.Fatal(err)
		}
		var got []byte
		select {
		case got = <-received:
		case <-time.After(100 * time.Millisecond):
			session.Close()
			raw.Close()
			listener.Close()
			t.Fatalf("raw bytes not delivered before kernel write (attempt %d)", attempt)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("raw stream %q", got)
		}
		_, _ = raw.Write(payload)
		session.Close()
		raw.Close()
		listener.Close()
	}
}

func TestDesyncHostDecoyAlwaysRejectedAtRealSequence(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("CAP_NET_RAW/CAP_NET_ADMIN required")
	}
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			host := "127.0.0.1:0"
			if network == "tcp6" {
				host = "[::1]:0"
			}
			listener, err := net.Listen(network, host)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			raw, err := net.Dial(network, listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			peer, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			session, err := NewDesyncSession(raw)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			decoy := []byte("DECOY-MUST-NOT-BE-ACCEPTED")
			if err = session.Send(DesyncPacket{Payload: decoy, Decoy: true, TTL: 64, Fooling: "none"}); err != nil {
				t.Fatal(err)
			}
			if err = peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, len(decoy))
			n, err := peer.Read(b)
			if timeout, ok := err.(net.Error); n != 0 || !ok || !timeout.Timeout() {
				t.Fatalf("server consumed decoy: %q, %v", b[:n], err)
			}
			if err = peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			real := []byte("ORIGINAL-SERVER-STREAM")
			if _, err = raw.Write(real); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(real))
			if _, err = io.ReadFull(peer, got); err != nil || !bytes.Equal(got, real) {
				t.Fatalf("server stream changed: %q, %v", got, err)
			}
		})
	}
}
