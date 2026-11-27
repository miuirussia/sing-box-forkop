//go:build integration

package desync

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	engine "github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func regressionAdaptivePipe(t *testing.T, options option.DesyncOptions, dialDelay time.Duration) (net.Conn, net.Conn) {
	t.Helper()
	yes := true
	options.AutoTune = &yes
	options.Adaptive = &option.DesyncAdaptiveOptions{Timeout: badoption.Duration(time.Second), MaxAttempts: 1}
	options, err := option.NormalizeDesyncOptions(options)
	if err != nil {
		t.Fatal(err)
	}
	a := NewAdaptive("regression", options)
	a.catalog = []option.DesyncOptions{options}
	t.Cleanup(func() { _ = a.Close() })
	var peer net.Conn
	conn, err := a.DialContext(context.Background(), M.ParseSocksaddr("example.com:443"), 0,
		func(ctx, lifetime context.Context, _ M.Socksaddr, opts option.DesyncOptions) (net.Conn, error) {
			if dialDelay > 0 {
				timer := time.NewTimer(dialDelay)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			var raw net.Conn
			raw, peer = net.Pipe()
			return engine.NewConn(lifetime, raw, opts)
		})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
	return conn, peer
}

type halfCloseScript struct{ scriptedConn }

func (c *halfCloseScript) CloseWrite() error { return nil }

func TestAdaptiveHalfCloseSealsClientHelloRetry(t *testing.T) {
	a := adaptiveForTest(t)
	dials := 0
	conn, err := a.DialContext(context.Background(), M.ParseSocksaddr("example.com:443"), 0,
		func(context.Context, context.Context, M.Socksaddr, option.DesyncOptions) (net.Conn, error) {
			dials++
			return &halfCloseScript{scriptedConn{reader: bytes.NewReader(nil)}}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write(helloForTest()); err != nil {
		t.Fatal(err)
	}
	if err = N.CloseWrite(conn); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read side closed with FIN: %v", err)
	}
	if dials != 1 {
		t.Fatalf("ClientHello replayed after FIN: %d dials", dials)
	}
	if _, err = conn.Write([]byte("app")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write accepted after FIN: %v", err)
	}
	if a.Stats().Active != 0 {
		t.Fatal("half-close retained retry permit")
	}
}

func TestAdaptiveInitialWriteObeysTotalBudget(t *testing.T) {
	conn, peer := regressionAdaptivePipe(t, option.DesyncOptions{Mode: "multi_split", SplitPos: "1,2,3", Delay: badoption.Duration(time.Second)}, 0)
	done := make(chan struct{})
	go func() { defer close(done); _, _ = io.Copy(io.Discard, peer) }()
	start := time.Now()
	_, err := conn.Write(helloForTest())
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Errorf("initial write escaped budget: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Errorf("1s budget took %s", elapsed)
	}
	_ = conn.Close()
	<-done
}

func TestAdaptiveAssemblyCannotSendAfterDialConsumesBudget(t *testing.T) {
	conn, peer := regressionAdaptivePipe(t, option.DesyncOptions{Mode: "split", SplitPos: "1"}, 900*time.Millisecond)
	got := make(chan []byte, 1)
	go func() {
		_ = peer.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
		data, _ := io.ReadAll(peer)
		got <- data
	}()
	if _, err := conn.Write(helloForTest()[:2]); err != nil {
		t.Fatal(err)
	}
	// Keep the connection alive after the read timeout so a late assembly timer
	// cannot hide behind the caller's Close.
	_, _ = conn.Read(make([]byte, 1))
	if data := <-got; len(data) != 0 {
		t.Fatalf("buffer sent after total budget: %x", data)
	}
}

func TestAdaptivePartialHelloRemainsBoundedAfterAssemblyFallback(t *testing.T) {
	conn, peer := regressionAdaptivePipe(t, option.DesyncOptions{Mode: "split", SplitPos: "1"}, 0)
	hello := helloForTest()
	first := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := io.ReadFull(peer, make([]byte, 2))
		first <- err
		_, _ = io.Copy(io.Discard, peer)
	}()
	if _, err := conn.Write(hello[:2]); err != nil {
		t.Fatal(err)
	}
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	_, err := conn.Write(hello[2:])
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Errorf("late ClientHello escaped total budget: %v", err)
	}
	_ = conn.Close()
	<-done
}

func TestAdaptiveRestoresCallerDeadlinesAfterInitialExchange(t *testing.T) {
	conn, peer := regressionAdaptivePipe(t, option.DesyncOptions{Mode: "split", SplitPos: "1"}, 0)
	hello := helloForTest()
	result := make(chan error, 1)
	go func() {
		data := make([]byte, len(hello))
		_, err := io.ReadFull(peer, data)
		if err == nil && !bytes.Equal(data, hello) {
			err = errors.New("hello changed")
		}
		if err == nil {
			_, err = peer.Write([]byte("response"))
		}
		if err == nil {
			_, err = io.ReadFull(peer, data[:3])
		}
		if err == nil && string(data[:3]) != "app" {
			err = errors.New("application changed")
		}
		if err == nil {
			_, err = peer.Write([]byte("ok"))
		}
		result <- err
	}()
	if err := conn.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, len("response"))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := conn.Write([]byte("app")); err != nil {
		t.Fatalf("budget leaked into established write: %v", err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Fatalf("budget leaked into established read: %v", err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("later")); err == nil {
		t.Fatal("caller deadline was discarded")
	}
}
