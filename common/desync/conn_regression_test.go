package desync

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

type flightWrites struct {
	helloCapture
	writes int
}

func (c *flightWrites) Write(p []byte) (int, error) {
	c.writes++
	return c.Buffer.Write(p)
}

func TestSemanticStrategyPassesUnrelatedProtocols(t *testing.T) {
	for _, mode := range []string{"split", "multi_split", "tlsrec"} {
		for _, tc := range []struct {
			name string
			data []byte
		}{
			{"socks", []byte{5, 1, 0}},
			{"vless", []byte{0, 1, 2, 3, 4, 5, 6}},
			{"binary_tls_byte_collision", []byte{22, 255, 0, 1, 2, 3}},
			{"hostless_http", []byte("GET / HTTP/1.0\r\n\r\n")},
			{"tls_without_sni", testHello(t, "")},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				target := new(flightWrites)
				conn, err := NewConn(context.Background(), target, option.DesyncOptions{Mode: mode, SplitPos: "midsld"})
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				if n, err := conn.Write(tc.data); err != nil || n != len(tc.data) {
					t.Fatalf("write: %d %v", n, err)
				}
				if !bytes.Equal(target.Bytes(), tc.data) {
					t.Fatalf("stream changed: %x", target.Bytes())
				}
			})
		}
	}
}

func TestNumericStrategyStillSplitsBinaryFlight(t *testing.T) {
	target := new(flightWrites)
	conn, err := NewConn(context.Background(), target, option.DesyncOptions{Mode: "split", SplitPos: "1"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	data := []byte{5, 1, 0}
	if _, err = conn.Write(data); err != nil {
		t.Fatal(err)
	}
	if target.writes != 2 || !bytes.Equal(target.Bytes(), data) {
		t.Fatalf("writes=%d data=%x", target.writes, target.Bytes())
	}
}

func TestSemanticOffsetOutsideExistingHostStillFails(t *testing.T) {
	target := new(flightWrites)
	conn, err := NewConn(context.Background(), target, option.DesyncOptions{Mode: "split", SplitPos: "midsld+99999"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err == nil {
		t.Fatal("invalid offset was ignored")
	}
}

func TestCloseWritePartialFlushFailureIsTerminal(t *testing.T) {
	failure := errors.New("partial initial flush failed")
	target := &shortConn{chunk: 3, err: failure}
	conn, err := NewConn(context.Background(), target, option.DesyncOptions{Mode: "split", SplitPos: "1"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write([]byte("GET /")); err != nil {
		t.Fatal(err)
	}
	if err = conn.(*Conn).CloseWrite(); !errors.Is(err, failure) {
		t.Fatalf("flush error lost: %v", err)
	}
	before := target.bytes()
	target.mu.Lock()
	target.err = nil
	target.mu.Unlock()
	if _, err = conn.Write([]byte("later application")); err == nil {
		t.Fatal("accepted application bytes after partial initial flush failure")
	}
	if !bytes.Equal(before, target.bytes()) {
		t.Fatal("stream continued after partial flush failure")
	}
}

type pendingFlightConn struct {
	shortConn
	entered, release chan struct{}
	deadline         time.Time
}

func (c *pendingFlightConn) Write(p []byte) (int, error) {
	close(c.entered)
	<-c.release
	return c.shortConn.Write(p)
}
func (c *pendingFlightConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = deadline
	return nil
}

func TestConnCopyHandoffWaitsForAsyncFlushAndDeadlineRestoration(t *testing.T) {
	target := &pendingFlightConn{shortConn: shortConn{chunk: 999}, entered: make(chan struct{}), release: make(chan struct{})}
	wrapped, err := NewConn(context.Background(), target, option.DesyncOptions{Mode: "split", SplitPos: "1"})
	if err != nil {
		t.Fatal(err)
	}
	defer wrapped.Close()
	release := sync.OnceFunc(func() { close(target.release) })
	defer release()
	conn := wrapped.(*Conn)
	if err = conn.SetFirstFlightDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write([]byte("GET /partial")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-target.entered:
	case <-time.After(time.Second):
		t.Fatal("assembly timer did not flush")
	}
	if conn.WriterReplaceable() {
		t.Fatal("pending asynchronous write exposed the socket")
	}
	latest := time.Now().Add(3 * time.Second)
	if err = conn.SetWriteDeadline(latest); err != nil {
		t.Fatal(err)
	}
	release()
	until := time.Now().Add(time.Second)
	for !conn.WriterReplaceable() && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if !conn.WriterReplaceable() {
		t.Fatal("successful asynchronous flush did not release writer")
	}
	target.mu.Lock()
	actual := target.deadline
	target.mu.Unlock()
	if actual != latest {
		t.Fatalf("handoff preceded deadline restoration: %s, want %s", actual, latest)
	}
}

type failedRestoreConn struct {
	shortConn
	err error
}

func (c *failedRestoreConn) SetWriteDeadline(time.Time) error { return c.err }

func TestConnCopyHandoffRejectsDeadlineRestoreFailure(t *testing.T) {
	failure := errors.New("restore deadline failed")
	target := &failedRestoreConn{shortConn: shortConn{chunk: 999}, err: failure}
	wrapped, err := NewConn(context.Background(), target, option.DesyncOptions{Mode: "split", SplitPos: "1"})
	if err != nil {
		t.Fatal(err)
	}
	defer wrapped.Close()
	if _, err = wrapped.Write([]byte{5, 1, 0}); !errors.Is(err, failure) {
		t.Fatalf("lost restoration failure: %v", err)
	}
	if wrapped.(*Conn).WriterReplaceable() {
		t.Fatal("failed deadline restoration exposed the socket")
	}
	if _, err = wrapped.Write([]byte("application")); err == nil {
		t.Fatal("continued after failed first-flight restoration")
	}
}
