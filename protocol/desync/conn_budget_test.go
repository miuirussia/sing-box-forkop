package desync

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
)

func budgetAdaptive(t *testing.T) *Adaptive {
	t.Helper()
	o, err := option.NormalizeDesyncOptions(option.DesyncOptions{Preset: "auto", Adaptive: &option.DesyncAdaptiveOptions{
		Timeout: badoption.Duration(time.Second), MaxConcurrent: 1,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return NewAdaptive("budget", o)
}

func budgetConn(t *testing.T, a *Adaptive, ctx context.Context) (*adaptiveConn, *scriptedConn) {
	t.Helper()
	raw := &scriptedConn{reader: bytes.NewReader(nil)}
	conn, err := a.DialContext(ctx, M.ParseSocksaddr("example.com:443"), 0,
		func(context.Context, context.Context, M.Socksaddr, option.DesyncOptions) (net.Conn, error) {
			return raw, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	return conn.(*adaptiveConn), raw
}

func TestAdaptiveProbeBudgetExpiresWithoutFurtherIO(t *testing.T) {
	for _, tc := range []struct {
		name   string
		flight []byte
	}{
		{"idle", nil}, {"partial_hello", helloForTest()[:3]}, {"unread_hello", helloForTest()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a := budgetAdaptive(t)
				defer a.Close()
				conn, raw := budgetConn(t, a, context.Background())
				defer conn.Close()
				if len(tc.flight) > 0 {
					if _, err := conn.Write(tc.flight); err != nil {
						t.Fatal(err)
					}
				}
				time.Sleep(time.Second)
				synctest.Wait()
				if snapshot := a.Stats(); snapshot.Active != 0 {
					t.Fatalf("expired permit retained: %d", snapshot.Active)
				}
				before := a.Stats()
				if len(before.Entries) != 0 {
					t.Fatal("client inactivity penalized strategy")
				}
				// Both EOF/error and a late response belong to the expired probe.
				_, _ = conn.Read(make([]byte, 16))
				raw.mu.Lock()
				raw.reader = bytes.NewReader([]byte("late response"))
				raw.mu.Unlock()
				_, _ = conn.Read(make([]byte, 16))
				raw.Close()
				_, _ = conn.Write([]byte("late application"))
				after := a.Stats()
				if !reflect.DeepEqual(before.Entries, after.Entries) {
					t.Fatalf("expired probe changed learning: before=%+v after=%+v", before.Entries, after.Entries)
				}
				conn.mu.Lock()
				if conn.probeTimer != nil || !conn.released || !conn.probeExpired {
					t.Error("expired probe retained timer/permit/replay")
				}
				conn.mu.Unlock()
			})
		})
	}
}

func TestAdaptiveProbeBudgetReleaseRaces(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for range 64 {
			a := budgetAdaptive(t)
			ctx, cancel := context.WithCancel(context.Background())
			conn, _ := budgetConn(t, a, ctx)
			_, _ = conn.Write(helloForTest()[:3])
			var group sync.WaitGroup
			for _, action := range []func(){
				func() { _ = conn.Close() }, cancel,
				func() { _, _ = conn.Read(make([]byte, 1)) },
				func() { _, _ = conn.Write([]byte("application")) },
				func() { _ = conn.SetDeadline(time.Now().Add(time.Second)) },
			} {
				group.Go(func() { time.Sleep(time.Second); action() })
			}
			group.Wait()
			synctest.Wait()
			if a.Stats().Active != 0 {
				t.Fatal("release race retained permit")
			}
			fresh, _ := budgetConn(t, a, context.Background())
			_ = conn.Close()
			cancel()
			synctest.Wait()
			if a.Stats().Active != 1 {
				t.Fatal("old probe released a new connection's permit")
			}
			_ = fresh.Close()
			synctest.Wait()
			conn.mu.Lock()
			if conn.probeTimer != nil {
				t.Error("closed probe retained budget timer")
			}
			conn.mu.Unlock()
			if a.Stats().Active != 0 {
				t.Fatal("fresh connection leaked permit")
			}
			_ = a.Close()
		}
	})
}

func TestAdaptiveProbeBudgetRatesWaitingHelloTimeoutOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := budgetAdaptive(t)
		a.options.Adaptive.MaxAttempts = 1
		defer a.Close()
		raw, peer := net.Pipe()
		defer peer.Close()
		conn, err := a.DialContext(context.Background(), M.ParseSocksaddr("example.com:443"), 0,
			func(context.Context, context.Context, M.Socksaddr, option.DesyncOptions) (net.Conn, error) {
				return raw, nil
			})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		hello := helloForTest()
		go func() { _, _ = io.ReadFull(peer, make([]byte, len(hello))) }()
		if _, err = conn.Write(hello); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := conn.Read(make([]byte, 16)); done <- err }()
		synctest.Wait()
		time.Sleep(time.Second)
		synctest.Wait()
		if err = <-done; err == nil {
			t.Fatal("unanswered TLS read did not time out")
		}
		snapshot := a.Stats()
		if snapshot.Active != 0 || len(snapshot.Entries) == 0 {
			t.Fatal("timeout not released/rated")
		}
		for _, entry := range snapshot.Entries {
			if score := entry.Strategies[strategyID(a.catalog[0])]; score.Failure != 1 || score.Success != 0 {
				t.Fatalf("timeout rated more than once: %+v", score)
			}
		}
		_ = conn.Close()
		time.Sleep(time.Second)
		synctest.Wait()
		if !reflect.DeepEqual(snapshot.Entries, a.Stats().Entries) {
			t.Fatal("late cleanup changed timeout rating")
		}
	})
}

func TestAdaptiveProbeBudgetStopsAfterApplicationOrResponse(t *testing.T) {
	for _, flight := range [][]byte{[]byte("GET / HTTP/1.0\r\n\r\n"), {5, 1, 0}, helloForTest()} {
		t.Run(fmt.Sprintf("prefix_%x", flight[:3]), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a := budgetAdaptive(t)
				defer a.Close()
				conn, raw := budgetConn(t, a, context.Background())
				defer conn.Close()
				_, _ = conn.Write(flight)
				if flight[0] == 22 {
					raw.mu.Lock()
					raw.reader = bytes.NewReader([]byte("response"))
					raw.mu.Unlock()
					_, _ = conn.Read(make([]byte, 16))
				}
				conn.mu.Lock()
				if conn.probeTimer != nil {
					t.Error("completed initial probe retained timer")
				}
				conn.mu.Unlock()
				time.Sleep(2 * time.Second)
				synctest.Wait()
				if conn.probeExpired {
					t.Fatal("ordinary stream expired with initial probe")
				}
				raw.mu.Lock()
				raw.reader = bytes.NewReader([]byte("ordinary response"))
				raw.mu.Unlock()
				if n, err := conn.Read(make([]byte, 32)); n == 0 || err != nil {
					t.Fatalf("late ordinary response: %d %v", n, err)
				}
				if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
					t.Fatal(err)
				}
				if a.Stats().Active != 0 {
					t.Fatal("ordinary stream retained permit")
				}
			})
		})
	}
}

func TestAdaptiveProbeBudgetDuringReplacementDial(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := budgetAdaptive(t)
		defer a.Close()
		dials := 0
		retrying := make(chan struct{})
		conn, err := a.DialContext(context.Background(), M.ParseSocksaddr("example.com:443"), 0,
			func(ctx, _ context.Context, _ M.Socksaddr, _ option.DesyncOptions) (net.Conn, error) {
				dials++
				if dials == 1 {
					return &scriptedConn{reader: bytes.NewReader(nil)}, nil
				}
				close(retrying)
				<-ctx.Done()
				return nil, ctx.Err()
			})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err = conn.Write(helloForTest()); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := conn.Read(make([]byte, 16)); done <- err }()
		<-retrying
		time.Sleep(time.Second)
		synctest.Wait()
		if err = <-done; err == nil {
			t.Fatal("expired replacement dial succeeded")
		}
		if a.Stats().Active != 0 {
			t.Fatal("replacement dial retained expired permit")
		}
		for _, entry := range a.Stats().Entries {
			if len(entry.Strategies) != 1 || entry.Strategies[strategyID(a.catalog[0])].Failure != 1 {
				t.Fatalf("post-budget replacement error poisoned learning: %+v", entry.Strategies)
			}
		}
		wrapped := conn.(*adaptiveConn)
		wrapped.mu.Lock()
		if wrapped.probeTimer != nil || wrapped.retryTimer != nil {
			t.Error("expired replacement retained timers")
		}
		wrapped.mu.Unlock()
	})
}

func TestAdaptiveProbeBudgetPreservesCallerDeadlines(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := budgetAdaptive(t)
		defer a.Close()
		raw, peer := net.Pipe()
		defer peer.Close()
		dials := 0
		conn, err := a.DialContext(context.Background(), M.ParseSocksaddr("example.com:443"), 0,
			func(context.Context, context.Context, M.Socksaddr, option.DesyncOptions) (net.Conn, error) {
				dials++
				return raw, nil
			})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err = conn.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
			t.Fatal(err)
		}
		server := make(chan error, 1)
		go func() {
			_, err := io.ReadFull(peer, make([]byte, 3))
			if err == nil {
				time.Sleep(1200 * time.Millisecond)
				_, err = peer.Write([]byte("late"))
			}
			if err == nil {
				var application [4]byte
				_, err = io.ReadFull(peer, application[:])
				if err == nil && string(application[:]) != "once" {
					err = fmt.Errorf("application changed: %q", application)
				}
			}
			server <- err
		}()
		if _, err = conn.Write(helloForTest()[:3]); err != nil {
			t.Fatal(err)
		}
		read := make(chan error, 1)
		go func() {
			var reply [4]byte
			_, err := io.ReadFull(conn, reply[:])
			if err == nil && string(reply[:]) != "late" {
				err = fmt.Errorf("response changed: %q", reply)
			}
			read <- err
		}()
		time.Sleep(500 * time.Millisecond)
		if err = conn.SetReadDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(600 * time.Millisecond)
		synctest.Wait()
		if a.Stats().Active != 0 {
			t.Fatal("waiting partial greeting retained expired permit")
		}
		if err = <-read; err != nil {
			t.Fatalf("expiry changed cleared caller read deadline: %v", err)
		}
		if _, err = conn.Write([]byte("once")); err != nil {
			t.Fatalf("caller write deadline not restored after response: %v", err)
		}
		if err = <-server; err != nil {
			t.Fatal(err)
		}
		if err = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, err = conn.Read(make([]byte, 1)); err == nil {
			t.Fatal("caller read deadline ignored")
		}
		if err = conn.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err = conn.Write([]byte("later")); err == nil {
			t.Fatal("caller write deadline ignored")
		}
		if dials != 1 || len(a.Stats().Entries) != 0 {
			t.Fatal("expired probe replayed or learned stale traffic/errors")
		}
	})
}

func TestAdaptiveProbeBudgetIncludesDialAndBlockedWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := budgetAdaptive(t)
		defer a.Close()
		raw, peer := net.Pipe()
		defer peer.Close()
		conn, err := a.DialContext(context.Background(), M.ParseSocksaddr("example.com:443"), 0,
			func(context.Context, context.Context, M.Socksaddr, option.DesyncOptions) (net.Conn, error) {
				time.Sleep(900 * time.Millisecond)
				return raw, nil
			})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		done := make(chan error, 1)
		go func() { _, err := conn.Write(helloForTest()); done <- err }()
		synctest.Wait()
		if a.Stats().Active != 1 {
			t.Fatal("probe released before budget")
		}
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		if a.Stats().Active != 0 {
			t.Fatal("blocked first write exceeded original dial budget")
		}
		if err = <-done; err == nil {
			t.Fatal("blocked first write did not time out")
		}
		if len(a.Stats().Entries) != 0 {
			t.Fatal("unsent/stale ClientHello error changed learning")
		}
	})
}

func TestAdaptiveProbeBudgetTimersBoundedAndCleanedOnShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := budgetAdaptive(t)
		var conns []*adaptiveConn
		timers := 0
		for i := range 32 {
			conn, err := a.DialContext(context.Background(), M.ParseSocksaddr(fmt.Sprintf("host%d.example:443", i)), 0,
				func(context.Context, context.Context, M.Socksaddr, option.DesyncOptions) (net.Conn, error) {
					return &scriptedConn{reader: bytes.NewReader(nil)}, nil
				})
			if err != nil {
				t.Fatal(err)
			}
			wrapped := conn.(*adaptiveConn)
			if wrapped.probeTimer != nil {
				timers++
			}
			conns = append(conns, wrapped)
		}
		if timers != 16 || a.Stats().Active != 16 {
			t.Fatalf("unbounded probe timers/permits: %d/%d", timers, a.Stats().Active)
		}
		_ = a.Close()
		var group sync.WaitGroup
		for _, conn := range conns {
			group.Go(func() { _ = conn.Close() })
		}
		group.Wait()
		synctest.Wait()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		for _, conn := range conns {
			if conn.probeTimer != nil {
				t.Fatal("shutdown retained timer")
			}
		}
		if a.Stats().Active != 0 || len(a.Stats().Entries) != 0 {
			t.Fatal("shutdown leaked permits or learned stale errors")
		}
	})
}
