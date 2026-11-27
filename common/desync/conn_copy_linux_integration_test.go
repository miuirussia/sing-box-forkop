//go:build linux && integration

package desync

import (
	"bytes"
	"context"
	"io"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

// Observe actual splice calls independently of replaceability. writev also uses
// RawConn.Write, so distinguish its caller when the default copy loop upgrades.
type copyProbeConn struct {
	*net.TCPConn
	writes, spliceWrites atomic.Int64
}

func (c *copyProbeConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	return c.TCPConn.Write(p)
}
func (c *copyProbeConn) SyscallConn() (syscall.RawConn, error) {
	raw, err := c.TCPConn.SyscallConn()
	return &copyProbeRawConn{RawConn: raw, writes: &c.spliceWrites}, err
}

type copyProbeRawConn struct {
	syscall.RawConn
	writes *atomic.Int64
}

func (c *copyProbeRawConn) Write(f func(uintptr) bool) error {
	if pc, _, _, ok := runtime.Caller(1); ok && strings.HasSuffix(runtime.FuncForPC(pc).Name(), "/bufio.splice") {
		c.writes.Add(1)
	}
	return c.RawConn.Write(f)
}

func copyTCPPair(t testing.TB) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	for _, conn := range []net.Conn{client, server} {
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	}
	return client.(*net.TCPConn), server.(*net.TCPConn)
}

func TestConnRelayCopyUpgradesAfterFirstFlight(t *testing.T) {
	for _, mode := range []string{"split", "tlsrec", "assembly_timeout"} {
		t.Run(mode, func(t *testing.T) {
			sender, source := copyTCPPair(t)
			target, receiver := copyTCPPair(t)
			probe := &copyProbeConn{TCPConn: target}
			opts := option.DesyncOptions{Mode: mode, SplitPos: "midsld"}
			flight := testHello(t, "www.example.com")
			wantFlight := flight
			if mode == "tlsrec" {
				cuts, err := positions(flight, opts.SplitPos)
				if err != nil {
					t.Fatal(err)
				}
				wantFlight, err = recordSplit(flight, cuts)
				if err != nil {
					t.Fatal(err)
				}
			} else if mode == "assembly_timeout" {
				opts.Mode = "split"
				flight = []byte("GET /partial HTTP/1.1\r\nHost: example")
				wantFlight = flight
			}
			conn, err := NewConn(context.Background(), probe, opts)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			var counted atomic.Int64
			destination := bufio.NewCounterConn(conn, nil, []N.CountFunc{func(n int64) { counted.Add(n) }})
			type result struct {
				n   int64
				err error
			}
			done := make(chan result, 1)
			go func() {
				n, err := bufio.Copy(destination, source)
				if err == nil {
					err = N.CloseWrite(destination)
				}
				done <- result{n, err}
			}()
			// The same copy starts before the transform, then must recheck its
			// destination and upgrade. A true getter alone cannot pass this test.
			if _, err = sender.Write(flight); err != nil {
				t.Fatal(err)
			}
			gotFlight := make([]byte, len(wantFlight))
			if _, err = io.ReadFull(receiver, gotFlight); err != nil || !bytes.Equal(gotFlight, wantFlight) {
				t.Fatalf("first flight changed: %x, %v", gotFlight, err)
			}
			body := bytes.Repeat([]byte("relay payload\x00\xff"), 256*1024)
			go func() {
				_, _ = sender.Write(body)
				_ = sender.CloseWrite()
			}()
			got, err := io.ReadAll(receiver)
			if err != nil || !bytes.Equal(got, body) {
				t.Fatalf("body changed: got %d bytes, %v", len(got), err)
			}
			copied := <-done
			want := int64(len(flight) + len(body))
			if copied.err != nil || copied.n != want || counted.Load() != want {
				t.Fatalf("copy/counters: %+v, counted %d, want %d", copied, counted.Load(), want)
			}
			if probe.writes.Load() == 0 || probe.spliceWrites.Load() == 0 {
				t.Fatalf("copy never upgraded from transforms to splice: ordinary=%d splice=%d", probe.writes.Load(), probe.spliceWrites.Load())
			}
			// FIN from the real relay must preserve the response direction.
			if _, err = receiver.Write([]byte("response after FIN")); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, len("response after FIN"))
			if _, err = io.ReadFull(conn, response); err != nil || string(response) != "response after FIN" {
				t.Fatalf("half-close lost response: %q, %v", response, err)
			}
			if _, err = conn.Write([]byte("after FIN")); err == nil {
				t.Fatal("write accepted after FIN")
			}
		})
	}
}

func TestConnRelayCopyControlsAfterHandoff(t *testing.T) {
	for _, action := range []string{"deadline", "close", "cancel"} {
		t.Run(action, func(t *testing.T) {
			sender, source := copyTCPPair(t)
			target, receiver := copyTCPPair(t)
			probe := &copyProbeConn{TCPConn: target}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			conn, err := NewConn(ctx, probe, option.DesyncOptions{Mode: "split", SplitPos: "1"})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			done := make(chan error, 1)
			go func() { _, err := bufio.Copy(conn, source); done <- err }()
			flight := []byte{5, 1, 0}
			if _, err = sender.Write(flight); err != nil {
				t.Fatal(err)
			}
			if _, err = io.ReadFull(receiver, make([]byte, len(flight))); err != nil {
				t.Fatal(err)
			}
			sent := make(chan struct{})
			go func() {
				defer close(sent)
				_, _ = sender.Write(make([]byte, 32<<20))
				_ = sender.CloseWrite()
			}()
			if _, err = io.ReadFull(receiver, make([]byte, 65536)); err != nil {
				t.Fatal(err)
			}
			if probe.spliceWrites.Load() == 0 {
				t.Fatal("control was not tested on the optimized copy path")
			}
			switch action {
			case "deadline":
				err = conn.SetWriteDeadline(time.Now().Add(-time.Second))
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
				if err == nil {
					t.Fatal("interrupted splice completed successfully")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("deadline/close/cancellation did not interrupt splice")
			}
			_ = source.Close()
			<-sent
			if conn.(*Conn).WriterReplaceable() {
				t.Fatal("interrupted connection exposed its writer")
			}
		})
	}
}
