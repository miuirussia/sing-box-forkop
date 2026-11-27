package desync

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// shortConn exercises short writes without relying on TCP segmentation.
type shortConn struct {
	helloCapture
	mu     sync.Mutex
	chunk  int
	closed bool
	err    error
}

func (c *shortConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	n := min(c.chunk, len(b))
	_, _ = c.Buffer.Write(b[:n])
	return n, c.err
}
func (c *shortConn) Close() error { c.mu.Lock(); defer c.mu.Unlock(); c.closed = true; return nil }
func (c *shortConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.Buffer.Bytes()...)
}
func TestConnAssemblesAndHandlesShortWrites(t *testing.T) {
	hello := testHello(t, "www.example.com")
	target := &shortConn{chunk: 7}
	wrapped, err := NewConn(context.Background(), target, option.DesyncOptions{Mode: "multi_split", SplitPos: "sniext+1,midsld,endhost-1"})
	if err != nil {
		t.Fatal(err)
	}
	defer wrapped.Close()
	for i := 0; i < len(hello); i++ {
		n, err := wrapped.Write(hello[i : i+1])
		if err != nil || n != 1 {
			t.Fatalf("byte %d: %d %v", i, n, err)
		}
		if i < len(hello)-1 && len(target.bytes()) != 0 {
			t.Fatal("incomplete hello forwarded")
		}
		if i < len(hello)-1 && wrapped.(*Conn).WriterReplaceable() {
			t.Fatal("incomplete hello exposed the underlying writer")
		}
	}
	if !bytes.Equal(target.bytes(), hello) {
		t.Fatal("stream changed")
	}
	if !wrapped.(*Conn).WriterReplaceable() {
		t.Fatal("completed short writes did not release the writer")
	}
}
func TestConnDoesNotReplayAfterPartialFailure(t *testing.T) {
	failure := errors.New("injected write failure")
	target := &shortConn{chunk: 3, err: failure}
	wrapped, err := NewConn(context.Background(), target, option.DesyncOptions{Mode: "split", SplitPos: "1"})
	if err != nil {
		t.Fatal(err)
	}
	defer wrapped.Close()
	b := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	_, err = wrapped.Write(b)
	if !errors.Is(err, failure) {
		t.Fatalf("%v", err)
	}
	if wrapped.(*Conn).WriterReplaceable() {
		t.Fatal("partial failure exposed the underlying writer")
	}
	before := target.bytes()
	_, _ = wrapped.Write(b)
	if !bytes.Equal(before, target.bytes()) {
		t.Fatal("failed request replayed")
	}
}
func TestConnDeadlineAndCloseInterruptDelay(t *testing.T) {
	for _, tc := range []struct {
		name string
		stop func(net.Conn, context.CancelFunc)
		want error
	}{{"deadline", func(c net.Conn, _ context.CancelFunc) { _ = c.SetWriteDeadline(time.Now().Add(-time.Second)) }, os.ErrDeadlineExceeded}, {"close", func(c net.Conn, _ context.CancelFunc) { _ = c.Close() }, net.ErrClosed}, {"cancel", func(_ net.Conn, cancel context.CancelFunc) { cancel() }, context.Canceled}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			target := &shortConn{chunk: 999}
			wrapped, err := NewConn(ctx, target, option.DesyncOptions{Mode: "split", SplitPos: "1", Delay: badoption.Duration(5 * time.Second)})
			if err != nil {
				t.Fatal(err)
			}
			defer wrapped.Close()
			done := make(chan error, 1)
			go func() { _, err := wrapped.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); done <- err }()
			until := time.Now().Add(time.Second)
			for len(target.bytes()) == 0 && time.Now().Before(until) {
				time.Sleep(time.Millisecond)
			}
			tc.stop(wrapped, cancel)
			select {
			case err := <-done:
				if !errors.Is(err, tc.want) {
					t.Fatalf("got %v want %v", err, tc.want)
				}
			case <-time.After(time.Second):
				t.Fatal("write did not unblock")
			}
		})
	}
}
func TestConnAssemblyTimeoutFlushesOriginal(t *testing.T) {
	target := &shortConn{chunk: 2}
	wrapped, err := NewConn(context.Background(), target, option.DesyncOptions{Mode: "split", SplitPos: "midsld"})
	if err != nil {
		t.Fatal(err)
	}
	defer wrapped.Close()
	b := []byte("GET / HTTP/1.1\r\nHost: partial")
	_, err = wrapped.Write(b)
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Second)
	for len(target.bytes()) < len(b) && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if !bytes.Equal(target.bytes(), b) {
		t.Fatal("assembly timeout lost partial bytes")
	}
}
func TestWriteAllRejectsZeroProgress(t *testing.T) {
	if err := writeAll(&shortConn{}, []byte{1}); err != io.ErrShortWrite {
		t.Fatal(err)
	}
}
