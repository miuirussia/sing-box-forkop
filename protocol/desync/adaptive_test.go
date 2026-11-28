package desync

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func helloForTest() []byte {
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0, 0, 0)
	message := append([]byte{1, 0, 0, byte(len(body))}, body...)
	return append([]byte{22, 3, 1, byte(len(message) >> 8), byte(len(message))}, message...)
}
func TestReplayableClientHello(t *testing.T) {
	hello := helloForTest()
	if !ReplayableClientHello(hello) {
		t.Fatal("valid hello rejected")
	}
	for i := 0; i < len(hello); i++ {
		if ReplayableClientHello(hello[:i]) {
			t.Fatalf("accepted incomplete prefix %d", i)
		}
	}
	for _, bad := range [][]byte{append(append([]byte{}, hello...), 23, 3, 3, 0, 1, 0), []byte("GET / HTTP/1.1\r\nHost:example.com\r\n\r\n"), append(append([]byte{}, hello...), hello...)} {
		if ReplayableClientHello(bad) {
			t.Fatal("accepted unsafe flight")
		}
	}
	early := append([]byte{}, hello...)
	early = append(early, 0, 42, 0, 0)
	binary.BigEndian.PutUint16(early[3:5], uint16(len(early)-5))
	early[8] = byte(len(early) - 9)
	binary.BigEndian.PutUint16(early[len(hello)-2:len(hello)], 4)
	if ReplayableClientHello(early) {
		t.Fatal("accepted early_data extension")
	}
	split := append([]byte{22, 3, 1, 0, 8}, hello[5:13]...)
	split = append(split, 22, 3, 1, 0, byte(len(hello)-13))
	split = append(split, hello[13:]...)
	if !ReplayableClientHello(split) {
		t.Fatal("fragmented handshake rejected")
	}
}

type scriptedConn struct {
	mu      sync.Mutex
	reader  *bytes.Reader
	written bytes.Buffer
	closed  bool
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	return c.reader.Read(p)
}
func (c *scriptedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	return c.written.Write(p)
}
func (c *scriptedConn) Close() error { c.mu.Lock(); c.closed = true; c.mu.Unlock(); return nil }
func (c *scriptedConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}
func (c *scriptedConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 443}
}
func (c *scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }
func adaptiveForTest(t *testing.T) *Adaptive {
	t.Helper()
	o, err := option.NormalizeDesyncOptions(option.DesyncOptions{Preset: "auto"})
	if err != nil {
		t.Fatal(err)
	}
	a := NewAdaptive("test", o)
	a.catalog = []option.DesyncOptions{o, o, o}
	a.catalog[0].Mode = "split"
	a.catalog[1].Mode = "tlsrec"
	a.catalog[2].Mode = "multi_split"
	t.Cleanup(func() { _ = a.Close() })
	return a
}
func TestAdaptiveSafeRetry(t *testing.T) {
	for _, tc := range []struct {
		name      string
		flight    []byte
		response  []byte
		wantDials int
	}{{"hello", helloForTest(), nil, 2}, {"http", []byte("GET / HTTP/1.1\r\n\r\n"), nil, 1}, {"application after hello", append(helloForTest(), 23, 3, 3, 0, 1, 0), nil, 1}, {"server bytes seal retry", helloForTest(), []byte{22}, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			a := adaptiveForTest(t)
			var conns []*scriptedConn
			dial := func(ctx, lifetime context.Context, d M.Socksaddr, o option.DesyncOptions) (net.Conn, error) {
				if ctx.Err() != nil || lifetime.Err() != nil {
					t.Fatal("cancelled dial")
				}
				response := tc.response
				if len(conns) > 0 {
					response = []byte("server hello")
				}
				c := &scriptedConn{reader: bytes.NewReader(response)}
				conns = append(conns, c)
				return c, nil
			}
			conn, err := a.DialContext(context.Background(), M.ParseSocksaddr("example.com:443"), 0, dial)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err = conn.Write(tc.flight); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 1024)
			_, _ = conn.Read(buf)
			_, _ = conn.Read(buf)
			if len(conns) != tc.wantDials {
				t.Fatalf("dials %d want %d", len(conns), tc.wantDials)
			}
			if tc.wantDials == 2 && !bytes.Equal(conns[1].written.Bytes(), tc.flight) {
				t.Fatal("replay changed flight")
			}
			if a.Stats().Active != 0 {
				t.Fatal("probe permit leaked")
			}
		})
	}
}
func TestAdaptiveBoundsAndPartition(t *testing.T) {
	a := adaptiveForTest(t)
	for i := 0; i < a.options.Adaptive.MaxConcurrent; i++ {
		if !a.acquire("host") {
			t.Fatal("permit refused")
		}
	}
	if a.acquire("host") {
		t.Fatal("concurrency limit exceeded")
	}
	for i := 0; i < a.options.Adaptive.MaxConcurrent; i++ {
		a.release("host")
	}
	for i := 0; i < 1100; i++ {
		a.observe([]string{string(rune(i))}, strategyID(a.catalog[0]), "failure", false, 0)
	}
	if len(a.Stats().Entries) > a.options.Adaptive.MaxEntries {
		t.Fatal("entry limit exceeded")
	}
	b := adaptiveForTest(t)
	b.options.Adaptive.NetworkID = "other"
	b = NewAdaptive("test", b.options)
	if a.partition == b.partition {
		t.Fatal("network context not partitioned")
	}
	a.mu.Lock()
	for _, e := range a.entries {
		e.Updated = time.Now().Add(-8 * 24 * time.Hour)
	}
	a.mu.Unlock()
	if len(a.Stats().Entries) != 0 {
		t.Fatal("TTL not applied")
	}
}

type memoryStore struct {
	mu     sync.Mutex
	data   []byte
	writes int
}

func (s *memoryStore) LoadDesync(string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.data...), nil
}
func (s *memoryStore) StoreDesync(_ string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = append([]byte(nil), data...)
	s.writes++
	return nil
}
func (s *memoryStore) ClearDesync(string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = nil
	return nil
}
func TestAdaptivePersistence(t *testing.T) {
	a := adaptiveForTest(t)
	store := new(memoryStore)
	a.store = store
	keys := destinationKeys(M.ParseSocksaddr("example.com:443"), 0)
	for range 10 {
		a.observe(keys, strategyID(a.catalog[1]), "response", true, time.Millisecond)
	}
	if store.writes != 0 {
		t.Fatal("wrote every event")
	}
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}
	b := adaptiveForTest(t)
	b.store = store
	if err := b.Load(); err != nil {
		t.Fatal(err)
	}
	if b.ranked(keys)[0].Mode != "tlsrec" {
		t.Fatal("did not restore learned winner")
	}
	if b.ranked(destinationKeys(M.ParseSocksaddr("example.com:443"), 1))[0].Mode == "tlsrec" {
		t.Fatal("route generation reused stale winner")
	}
	if err := b.Clear(); err != nil {
		t.Fatal(err)
	}
	if len(b.Stats().Entries) != 0 {
		t.Fatal("clear left in-memory state")
	}
	var snap Snapshot
	_ = json.Unmarshal(store.data, &snap)
	if len(snap.Entries) != 0 {
		t.Fatal("clear left persisted state")
	}
}
func TestAdaptiveCancelClose(t *testing.T) {
	a := adaptiveForTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := a.DialContext(ctx, M.ParseSocksaddr("example.com:443"), 0, func(context.Context, context.Context, M.Socksaddr, option.DesyncOptions) (net.Conn, error) {
		return &scriptedConn{reader: bytes.NewReader(nil)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for a.Stats().Active != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if a.Stats().Active != 0 {
		t.Fatal("cancellation leaked permit")
	}
	if _, err = conn.Write([]byte("x")); err == nil {
		t.Fatal("cancelled conn still writable")
	}
	_ = conn.Close()
}
func FuzzReplayableHello(f *testing.F) {
	f.Add(helloForTest())
	f.Add([]byte("GET /"))
	f.Fuzz(func(t *testing.T, p []byte) {
		if len(p) > 65536 {
			t.Skip()
		}
		_ = ReplayableClientHello(p)
	})
}

func TestAdaptiveClosedDoesNotDial(t *testing.T) {
	a := adaptiveForTest(t)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	called := false
	_, err := a.DialContext(context.Background(), M.ParseSocksaddr("example.com:443"), 0, func(context.Context, context.Context, M.Socksaddr, option.DesyncOptions) (net.Conn, error) {
		called = true
		return nil, nil
	})
	if err == nil || called {
		t.Fatal("closed Adaptive opened socket")
	}
}

func TestAdaptiveCloseCancelsReplacementDial(t *testing.T) {
	a := adaptiveForTest(t)
	started := make(chan struct{})
	count := 0
	conn, err := a.DialContext(context.Background(), M.ParseSocksaddr("example.com:443"), 0, func(ctx, lifetime context.Context, d M.Socksaddr, o option.DesyncOptions) (net.Conn, error) {
		count++
		if count == 1 {
			return &scriptedConn{reader: bytes.NewReader(nil)}, nil
		}
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write(helloForTest()); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _, _ = conn.Read(make([]byte, 8)); close(done) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("retry did not start")
	}
	if err = conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close failed to cancel replacement dial")
	}
}

func TestAdaptiveDeadlineInterruptsReplacementDial(t *testing.T) {
	a := adaptiveForTest(t)
	started := make(chan struct{})
	count := 0
	conn, err := a.DialContext(context.Background(), M.ParseSocksaddr("example.com:443"), 0, func(ctx, lifetime context.Context, d M.Socksaddr, o option.DesyncOptions) (net.Conn, error) {
		count++
		if count == 1 {
			return &scriptedConn{reader: bytes.NewReader(nil)}, nil
		}
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write(helloForTest())
	done := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 8)); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("no retry")
	}
	if err = conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		timeout, ok := err.(net.Error)
		if !ok || !timeout.Timeout() {
			t.Fatalf("expected deadline error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("read deadline did not interrupt redial")
	}
}
