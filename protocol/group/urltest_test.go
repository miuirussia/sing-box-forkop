package group

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-box/adapter"
	outboundAdapter "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/miekg/dns"
)

func (g *URLTestGroup) storeHistory(tag string, history *adapter.URLTestHistory) {
	g.access.Lock()
	defer g.access.Unlock()
	g.storeHistoryLocked(tag, history)
}

func TestURLTestGroupHistoryIsIsolated(t *testing.T) {
	sharedHistory := urltest.NewHistoryStorage()
	ctx := service.ContextWithPtr(context.Background(), sharedHistory)
	first, err := NewURLTestGroup(ctx, nil, nil, nil, "", nil, 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewURLTestGroup(ctx, nil, nil, nil, "", nil, 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}

	first.storeHistory("node", &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	second.storeHistory("node", &adapter.URLTestHistory{Time: time.Now(), Delay: 20})
	second.history.DeleteURLTestHistory("node")
	sharedHistory.DeleteURLTestHistory("node")

	if history := first.history.LoadURLTestHistory("node"); history == nil || history.Delay != 10 {
		t.Fatal("one URLTest group deleted another group's history")
	}
	if second.history.LoadURLTestHistory("node") != nil {
		t.Fatal("failed URLTest group kept its local history")
	}
	if sharedHistory.LoadURLTestHistory("node") != nil {
		t.Fatal("dashboard still reports a delay for an outbound that just failed")
	}
}

type initialURLTestOutbound struct {
	*fallbackHealthTestOutbound
}

func (o *initialURLTestOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}

type urlTestDeadlineConnection interface {
	io.Closer
	SetReadDeadline(time.Time) error
}

type udpProbeTestOutbound struct {
	*fallbackHealthTestOutbound
	wrongReply bool
	beforeUDP  func(context.Context, M.Socksaddr) error
	openedUDP  func(urlTestDeadlineConnection)
}

func (o *udpProbeTestOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != N.NetworkUDP {
		return o.fallbackHealthTestOutbound.DialContext(ctx, network, destination)
	}
	if o.beforeUDP != nil {
		if err := o.beforeUDP(ctx, destination); err != nil {
			return nil, err
		}
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		buffer := make([]byte, 4096)
		count, err := server.Read(buffer)
		if err != nil {
			return
		}
		var query dns.Msg
		if query.Unpack(buffer[:count]) != nil {
			return
		}
		response := new(dns.Msg).SetReply(&query)
		if o.wrongReply {
			response.Id++
		}
		payload, err := response.Pack()
		if err == nil {
			_, _ = server.Write(payload)
		}
	}()
	if o.openedUDP != nil {
		o.openedUDP(client)
	}
	return client, nil
}

func (o *udpProbeTestOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if o.beforeUDP != nil {
		if err := o.beforeUDP(ctx, destination); err != nil {
			return nil, err
		}
	}
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err == nil && o.openedUDP != nil {
		o.openedUDP(conn)
	}
	return conn, err
}

func enableTestUDPProbe(t *testing.T, group *URLTestGroup) {
	t.Helper()
	probe, err := urltest.NewUDPProbe(M.ParseSocksaddr("192.0.2.53:53"), "health.test")
	if err != nil {
		t.Fatal(err)
	}
	group.setUDPProbe(probe)
}

func TestURLTestChecksUDPIndependentlyOfTCP(t *testing.T) {
	first := &udpProbeTestOutbound{fallbackHealthTestOutbound: newFallbackHealthTestOutbound("first", true), wrongReply: true}
	second := &udpProbeTestOutbound{fallbackHealthTestOutbound: newFallbackHealthTestOutbound("second", true)}
	group := newDialTestURLTest(t, first, second).group
	enableTestUDPProbe(t, group)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := group.selectForDial(ctx, N.NetworkUDP)
	if err != nil || got.outbound != second {
		t.Fatalf("UDP selection = %v, %v, want second", got.outbound, err)
	}
	got, err = group.selectForDial(ctx, N.NetworkTCP)
	if err != nil || got.outbound != first {
		t.Fatalf("TCP selection = %v, %v, want first", got.outbound, err)
	}
}

func TestURLTestPublishesHTTPWhileUDPIsStalled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		udpStarted := make(chan struct{})
		var firstUDP sync.Once
		member := &udpProbeTestOutbound{
			fallbackHealthTestOutbound: newFallbackHealthTestOutbound("exit", true),
			beforeUDP: func(ctx context.Context, _ M.Socksaddr) error {
				firstUDP.Do(func() { close(udpStarted) })
				<-ctx.Done()
				return ctx.Err()
			},
		}
		manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{member.Tag(): member}}
		group, err := NewURLTestGroup(ctx, manager, log.NewNOPFactory().NewLogger("test"),
			[]adapter.Outbound{member}, "http://health.test/", nil, 0, 0, 0, false)
		if err != nil {
			t.Fatal(err)
		}
		enableTestUDPProbe(t, group)
		group.PostStart()
		<-udpStarted
		synctest.Wait()
		group.access.RLock()
		selected := group.selectedOutboundTCP
		group.access.RUnlock()
		if selected != member {
			t.Fatalf("scheduled check kept the TCP selection pending: %v", selected)
		}
		dialCtx, cancelDial := context.WithTimeout(ctx, time.Second)
		defer cancelDial()
		start := time.Now()
		result, err := group.URLTest(dialCtx)
		if _, ok := result[member.Tag()]; err != nil || !ok {
			t.Fatalf("manual HTTP result = %v, %v", result, err)
		}
		if elapsed := time.Since(start); elapsed >= time.Second {
			t.Fatalf("manual HTTP result waited for UDP: %v", elapsed)
		}
	})
}

func TestURLTestCloseCancelsDashboardUDPProbe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		started := make(chan struct{})
		stopped := make(chan struct{})
		member := &udpProbeTestOutbound{
			fallbackHealthTestOutbound: newFallbackHealthTestOutbound("exit", true),
			beforeUDP: func(ctx context.Context, _ M.Socksaddr) error {
				close(started)
				<-ctx.Done()
				close(stopped)
				return ctx.Err()
			},
		}
		manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{member.Tag(): member}}
		group, err := NewURLTestGroup(ctx, manager, log.NewNOPFactory().NewLogger("test"),
			[]adapter.Outbound{member}, "http://health.test/", nil, 0, 0, 0, false)
		if err != nil {
			t.Fatal(err)
		}
		enableTestUDPProbe(t, group)
		requestCtx, cancelRequest := context.WithCancel(ctx)
		defer cancelRequest()
		if _, err := group.URLTest(requestCtx); err != nil {
			t.Fatal(err)
		}
		<-started
		cancelRequest()
		synctest.Wait()
		select {
		case <-stopped:
			t.Fatal("dashboard UDP probe stopped when the request ended")
		default:
		}
		if err := group.Close(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		select {
		case <-stopped:
		default:
			t.Fatal("dashboard UDP probe still running after group closed")
		}
	})
}

func TestURLTestFirstUDPConnectionJoinsScheduledProbe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := make(chan struct{}, 2)
		release := make(chan struct{})
		member := &udpProbeTestOutbound{
			fallbackHealthTestOutbound: newFallbackHealthTestOutbound("exit", true),
			beforeUDP: func(ctx context.Context, _ M.Socksaddr) error {
				started <- struct{}{}
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			},
		}
		manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{member.Tag(): member}}
		group, err := NewURLTestGroup(t.Context(), manager, log.NewNOPFactory().NewLogger("test"),
			[]adapter.Outbound{member}, "http://health.test/", nil, 0, 0, 0, false)
		if err != nil {
			t.Fatal(err)
		}
		enableTestUDPProbe(t, group)
		group.PostStart()
		<-started
		done := make(chan error, 1)
		go func() {
			_, err := group.selectForDial(t.Context(), N.NetworkUDP)
			done <- err
		}()
		synctest.Wait()
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if duplicates := len(started); duplicates != 0 {
			t.Fatalf("first connection started %d duplicate UDP probes", duplicates)
		}
	})
}

type splitURLTestOutbound struct {
	*fallbackHistoryGroupOutbound
	udp adapter.Outbound
}

func (o *splitURLTestOutbound) Selected(network string) adapter.Outbound {
	if network == N.NetworkUDP {
		return o.udp
	}
	return o.selected
}

func (o *splitURLTestOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return o.Selected(network).DialContext(ctx, network, destination)
}

func TestURLTestProbesTheNestedGroupsUDPExit(t *testing.T) {
	tcpExit := &udpProbeTestOutbound{fallbackHealthTestOutbound: newFallbackHealthTestOutbound("tcp-exit", true), wrongReply: true}
	udpExit := &udpProbeTestOutbound{fallbackHealthTestOutbound: newFallbackHealthTestOutbound("udp-exit", true)}
	nested := &splitURLTestOutbound{
		fallbackHistoryGroupOutbound: &fallbackHistoryGroupOutbound{
			fallbackHealthTestOutbound: newFallbackHealthTestOutbound("nested", true),
			selected:                   tcpExit,
		},
		udp: udpExit,
	}
	manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{
		nested.Tag(): nested, tcpExit.Tag(): tcpExit, udpExit.Tag(): udpExit,
	}}
	group, err := NewURLTestGroup(t.Context(), manager, log.NewNOPFactory().NewLogger("test"),
		[]adapter.Outbound{nested}, "http://health.test/generate_204", nil, time.Hour, 0, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	enableTestUDPProbe(t, group)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	for _, network := range []string{N.NetworkUDP, N.NetworkTCP} {
		got, err := group.selectForDial(ctx, network)
		if err != nil || got.outbound != nested {
			t.Fatalf("%s selection = %v, %v, want nested", network, got.outbound, err)
		}
	}
}

type urlTestTrackedCloser struct{ closed bool }

func (c *urlTestTrackedCloser) Close() error {
	c.closed = true
	return nil
}

func TestURLTestUDPFailureOnlyInterruptsUDP(t *testing.T) {
	for _, interruptExternal := range []bool{false, true} {
		t.Run(fmt.Sprintf("interrupt_external_%t", interruptExternal), func(t *testing.T) {
			member := &udpProbeTestOutbound{fallbackHealthTestOutbound: newFallbackHealthTestOutbound("exit", true)}
			outbound := newDialTestURLTest(t, member)
			group := outbound.group
			group.interruptExternalConnections = interruptExternal
			enableTestUDPProbe(t, group)
			group.CheckOutbounds(t.Context(), true)
			tcp, err := outbound.DialContext(t.Context(), N.NetworkTCP, M.ParseSocksaddr("192.0.2.1:80"))
			if err != nil {
				t.Fatal(err)
			}
			defer tcp.Close()
			udp, err := outbound.ListenPacket(t.Context(), M.ParseSocksaddr("192.0.2.1:51820"))
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			externalTCP, externalUDP := &urlTestTrackedCloser{}, &urlTestTrackedCloser{}
			defer outbound.AttachConnectionForNetwork(N.NetworkTCP, externalTCP)()
			defer outbound.AttachConnectionForNetwork(N.NetworkUDP, externalUDP)()

			member.wrongReply = true
			group.CheckOutbounds(t.Context(), true)

			if err = udp.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
				t.Errorf("UDP was not interrupted, setting a deadline returned %v", err)
			}
			if err = tcp.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err = io.WriteString(tcp, "GET / HTTP/1.0\r\n\r\n"); err != nil {
				t.Errorf("UDP probe interrupted TCP: %v", err)
			}
			if externalTCP.closed || externalUDP.closed != interruptExternal {
				t.Errorf("external connections closed: TCP = %t, UDP = %t, want TCP = false, UDP = %t",
					externalTCP.closed, externalUDP.closed, interruptExternal)
			}
		})
	}
}

func TestURLTestUDPDialSwitchInterruptsPreviousConnections(t *testing.T) {
	first := &udpProbeTestOutbound{fallbackHealthTestOutbound: newFallbackHealthTestOutbound("first", true)}
	second := &udpProbeTestOutbound{fallbackHealthTestOutbound: newFallbackHealthTestOutbound("second", true)}
	outbound := newDialTestURLTest(t, first, second)
	group := outbound.group
	enableTestUDPProbe(t, group)
	group.udpHistory.StoreURLTestHistory(first.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	group.udpHistory.StoreURLTestHistory(second.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 20})
	group.performUpdateCheck()
	if selected, err := group.selectForDial(t.Context(), N.NetworkUDP); err != nil || selected.outbound != first {
		t.Fatalf("initial UDP selection = %v, %v, want first", selected.outbound, err)
	}
	packet, err := outbound.ListenPacket(t.Context(), M.ParseSocksaddr("192.0.2.1:51820"))
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	group.udpHistory.DeleteURLTestHistory(first.Tag())
	if selected, err := group.selectForDial(t.Context(), N.NetworkUDP); err != nil || selected.outbound != second {
		t.Fatalf("UDP selection after failure = %v, %v, want second", selected.outbound, err)
	}
	if err := packet.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("previous UDP connection was not interrupted, setting a deadline returned %v", err)
	}
}

func TestURLTestRetriesUDPConnectionOpenedDuringSwitch(t *testing.T) {
	destination := M.ParseSocksaddr("192.0.2.1:51820")
	for _, test := range []struct {
		name string
		open func(*URLTest, context.Context) (urlTestDeadlineConnection, error)
	}{
		{"dial", func(outbound *URLTest, ctx context.Context) (urlTestDeadlineConnection, error) {
			return outbound.DialContext(ctx, N.NetworkUDP, destination)
		}},
		{"listen", func(outbound *URLTest, ctx context.Context) (urlTestDeadlineConnection, error) {
			return outbound.ListenPacket(ctx, destination)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			started := make(chan struct{})
			resume := make(chan struct{})
			var oldConn urlTestDeadlineConnection
			first := &udpProbeTestOutbound{
				fallbackHealthTestOutbound: newFallbackHealthTestOutbound("first", true),
				beforeUDP: func(ctx context.Context, _ M.Socksaddr) error {
					close(started)
					select {
					case <-resume:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				},
				openedUDP: func(conn urlTestDeadlineConnection) {
					oldConn = conn
					t.Cleanup(func() { conn.Close() })
				},
			}
			var openedOnSecond bool
			second := &udpProbeTestOutbound{
				fallbackHealthTestOutbound: newFallbackHealthTestOutbound("second", true),
				beforeUDP: func(context.Context, M.Socksaddr) error {
					openedOnSecond = true
					return nil
				},
			}
			outbound := newDialTestURLTest(t, first, second)
			group := outbound.group
			t.Cleanup(func() { group.Close() })
			enableTestUDPProbe(t, group)
			group.udpHistory.StoreURLTestHistory(first.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
			group.udpHistory.StoreURLTestHistory(second.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 100})
			group.performUpdateCheck()

			switched := make(chan struct{})
			go func() {
				defer close(switched)
				select {
				case <-started:
					group.udpHistory.DeleteURLTestHistory(first.Tag())
					group.performUpdateCheck()
				case <-ctx.Done():
				}
				close(resume)
			}()
			conn, err := test.open(outbound, ctx)
			<-switched
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if !openedOnSecond {
				t.Fatal("the connection opened on the old UDP member after switching")
			}
			if oldConn == nil {
				t.Fatal("the old member did not finish opening its connection")
			}
			if err = oldConn.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
				t.Errorf("old connection is still open: setting a deadline returned %v", err)
			}
			if err = conn.SetReadDeadline(time.Now()); err != nil {
				t.Errorf("replacement connection is unusable: %v", err)
			}
		})
	}
}

func TestURLTestStaleUDPFailureKeepsCurrentProbeResult(t *testing.T) {
	first := &udpProbeTestOutbound{fallbackHealthTestOutbound: newFallbackHealthTestOutbound("first", true)}
	second := newFallbackHealthTestOutbound("second", true)
	outbound := newDialTestURLTest(t, first, second)
	group := outbound.group
	defer group.Close()
	enableTestUDPProbe(t, group)
	group.udpHistory.StoreURLTestHistory(first.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	group.udpHistory.StoreURLTestHistory(second.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 100})
	group.performUpdateCheck()

	fresh := &adapter.URLTestHistory{Time: time.Now(), Delay: 10}
	attempts := 0
	first.beforeUDP = func(context.Context, M.Socksaddr) error {
		attempts++
		if attempts > 1 {
			return nil
		}
		group.udpHistory.DeleteURLTestHistory(first.Tag())
		group.performUpdateCheck()
		if selected := outbound.Selected(N.NetworkUDP); selected != second {
			t.Fatalf("selected %v after losing the first probe, want second", selected)
		}
		group.udpHistory.StoreURLTestHistory(first.Tag(), fresh)
		group.performUpdateCheck()
		if selected := outbound.Selected(N.NetworkUDP); selected != first {
			t.Fatalf("selected %v after the fresh probe, want first", selected)
		}
		return errors.New("old UDP attempt failed")
	}

	conn, err := outbound.ListenPacket(t.Context(), M.ParseSocksaddr("192.0.2.1:51820"))
	if conn != nil {
		defer conn.Close()
	}
	if history := group.udpHistory.LoadURLTestHistory(first.Tag()); history != fresh {
		t.Errorf("old dial error replaced the fresh UDP probe: got %v, want %v", history, fresh)
	}
	if err != nil || attempts != 2 {
		t.Fatalf("UDP listen returned %v after %d attempts, want a successful retry", err, attempts)
	}
}

func TestURLTestUDPFailureKeepsProbeUpdatedDuringDial(t *testing.T) {
	member := &udpProbeTestOutbound{fallbackHealthTestOutbound: newFallbackHealthTestOutbound("member", true)}
	outbound := newDialTestURLTest(t, member)
	group := outbound.group
	defer group.Close()
	enableTestUDPProbe(t, group)
	old := &adapter.URLTestHistory{Time: time.Now().Add(-time.Minute), Delay: 10}
	group.udpHistory.StoreURLTestHistory(member.Tag(), old)
	group.performUpdateCheck()

	destination := M.ParseSocksaddr("192.0.2.1:51820")
	dialErr := errors.New("UDP dial failed")
	var fresh *adapter.URLTestHistory
	member.beforeUDP = func(ctx context.Context, address M.Socksaddr) error {
		if address != destination {
			return nil
		}
		group.checkUDP(ctx, member.Tag(), member)
		fresh = group.udpHistory.LoadURLTestHistory(member.Tag())
		if fresh == nil || fresh == old {
			t.Fatal("UDP probe did not publish a fresh result")
		}
		return dialErr
	}
	conn, err := outbound.DialContext(t.Context(), N.NetworkUDP, destination)
	if conn != nil {
		defer conn.Close()
	}
	if !errors.Is(err, dialErr) {
		t.Fatalf("UDP dial returned %v, want %v", err, dialErr)
	}
	if history := group.udpHistory.LoadURLTestHistory(member.Tag()); history != fresh {
		t.Errorf("failed dial left UDP probe %v, want %v", history, fresh)
	}
}

func TestURLTestUDPFailureUsesDialedSelectorExit(t *testing.T) {
	first := &udpProbeTestOutbound{fallbackHealthTestOutbound: newFallbackHealthTestOutbound("first", true)}
	second := &udpProbeTestOutbound{fallbackHealthTestOutbound: newFallbackHealthTestOutbound("second", true)}
	selector := &Selector{
		Adapter: outboundAdapter.NewAdapter(C.TypeSelector, "selector", []string{N.NetworkTCP, N.NetworkUDP}, nil),
		ctx:     t.Context(),
		outbounds: map[string]adapter.Outbound{
			first.Tag(): first, second.Tag(): second,
		},
		interruptGroup: interrupt.NewGroup(),
	}
	selector.selected.Store(first)
	outbound := newDialTestURLTest(t, selector)
	group := outbound.group
	defer group.Close()
	enableTestUDPProbe(t, group)
	group.udpHistory.StoreURLTestHistory(first.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	secondProbe := &adapter.URLTestHistory{Time: time.Now(), Delay: 20}
	group.udpHistory.StoreURLTestHistory(second.Tag(), secondProbe)
	group.performUpdateCheck()

	dialErr := errors.New("first exit failed")
	first.beforeUDP = func(context.Context, M.Socksaddr) error {
		if !selector.SelectOutbound(second.Tag()) {
			t.Fatal("failed to switch the nested selector")
		}
		return dialErr
	}
	conn, err := outbound.ListenPacket(t.Context(), M.ParseSocksaddr("192.0.2.1:51820"))
	if conn != nil {
		defer conn.Close()
	}
	if !errors.Is(err, dialErr) {
		t.Fatalf("UDP listen returned %v, want %v", err, dialErr)
	}
	if history := group.udpHistory.LoadURLTestHistory(first.Tag()); history != nil {
		t.Errorf("failed exit kept its UDP probe %v", history)
	}
	if history := group.udpHistory.LoadURLTestHistory(second.Tag()); history != secondProbe {
		t.Errorf("new exit's UDP probe = %v, want %v", history, secondProbe)
	}
}

func TestURLTestUDPFailureWhenNestedGroupCannotSelect(t *testing.T) {
	for _, refreshProbe := range []bool{false, true} {
		t.Run(fmt.Sprintf("refresh_probe_%t", refreshProbe), func(t *testing.T) {
			exit := &udpProbeTestOutbound{fallbackHealthTestOutbound: newFallbackHealthTestOutbound("exit", true)}
			nested := newDialTestURLTest(t, exit)
			defer nested.group.Close()
			enableTestUDPProbe(t, nested.group)
			nested.group.performUpdateCheck()

			backup := &udpProbeTestOutbound{fallbackHealthTestOutbound: newFallbackHealthTestOutbound("backup", true)}
			parent := newDialTestURLTest(t, backup, nested)
			defer parent.group.Close()
			enableTestUDPProbe(t, parent.group)
			history := parent.group.udpHistory
			history.StoreURLTestHistory(exit.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
			backupProbe := &adapter.URLTestHistory{Time: time.Now(), Delay: 100}
			history.StoreURLTestHistory(backup.Tag(), backupProbe)
			parent.group.performUpdateCheck()
			if got := parent.Selected(N.NetworkUDP); got != nested {
				t.Fatalf("initial UDP selection = %v, want nested group", got)
			}

			freshProbe := &adapter.URLTestHistory{Time: time.Now(), Delay: 10}
			exit.beforeUDP = func(context.Context, M.Socksaddr) error {
				if refreshProbe {
					history.StoreURLTestHistory(exit.Tag(), freshProbe)
				}
				return errors.New("nested UDP probe failed")
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			destination := M.ParseSocksaddr("192.0.2.1:51820")
			conn, err := parent.ListenPacket(ctx, destination)
			if conn != nil {
				conn.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "no outbound passed the UDP probe") {
				t.Fatalf("UDP listen returned %v, want nested selection error", err)
			}
			if got := history.LoadURLTestHistory(backup.Tag()); got != backupProbe {
				t.Errorf("backup probe = %v, want %v", got, backupProbe)
			}
			if refreshProbe {
				if got := history.LoadURLTestHistory(exit.Tag()); got != freshProbe {
					t.Errorf("exit probe = %v, want refreshed probe %v", got, freshProbe)
				}
				return
			}
			conn, err = parent.ListenPacket(ctx, destination)
			if err != nil {
				t.Fatalf("second UDP listen failed with a probed backup available: %v", err)
			}
			defer conn.Close()
			if got := parent.Selected(N.NetworkUDP); got != backup {
				t.Errorf("UDP selection = %v, want backup", got)
			}
		})
	}
}

func TestURLTestUDPFailureInvalidatesFallbackExits(t *testing.T) {
	destination := M.ParseSocksaddr("192.0.2.1:51820")
	for _, test := range []struct {
		name         string
		backupProbed bool
		backupWorks  bool
		nested       bool
	}{
		{name: "unprobed backup fails"},
		{name: "probed backup fails", backupProbed: true},
		{name: "backup succeeds", backupProbed: true, backupWorks: true},
		{name: "nested URLTest fails", nested: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			first := &udpProbeTestOutbound{fallbackHealthTestOutbound: newFallbackHealthTestOutbound("first", true)}
			second := &udpProbeTestOutbound{fallbackHealthTestOutbound: newFallbackHealthTestOutbound("second", true)}
			fallback := newTestFallback(
				fallbackCandidate{tag: first.Tag(), outbound: first},
				fallbackCandidate{tag: second.Tag(), outbound: second},
			)
			fallback.Adapter = outboundAdapter.NewAdapter(C.TypeFallback, "fallback", []string{N.NetworkTCP, N.NetworkUDP}, nil)
			var member adapter.Outbound = fallback
			var nested *URLTest
			if test.nested {
				nested = newDialTestURLTest(t, fallback)
				defer nested.group.Close()
				enableTestUDPProbe(t, nested.group)
				nested.group.udpHistory.StoreURLTestHistory(first.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
				nested.group.performUpdateCheck()
				member = nested
			}
			alternate := &udpProbeTestOutbound{fallbackHealthTestOutbound: newFallbackHealthTestOutbound("alternate", true)}
			outbound := newDialTestURLTest(t, alternate, member)
			group := outbound.group
			defer group.Close()
			enableTestUDPProbe(t, group)
			firstProbe := &adapter.URLTestHistory{Time: time.Now(), Delay: 10}
			secondProbe := &adapter.URLTestHistory{Time: time.Now(), Delay: 20}
			group.udpHistory.StoreURLTestHistory(first.Tag(), firstProbe)
			if test.backupProbed {
				group.udpHistory.StoreURLTestHistory(second.Tag(), secondProbe)
			}
			group.udpHistory.StoreURLTestHistory(alternate.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 100})
			group.performUpdateCheck()
			if selected := outbound.Selected(N.NetworkUDP); selected != member {
				t.Fatalf("initial UDP outbound = %v, want %v", selected, member)
			}

			first.beforeUDP = func(context.Context, M.Socksaddr) error { return errors.New("first exit failed") }
			var dialErr error
			if !test.backupWorks {
				dialErr = errors.New("last exit failed")
			}
			second.beforeUDP = func(context.Context, M.Socksaddr) error { return dialErr }
			conn, err := outbound.ListenPacket(t.Context(), destination)
			if conn != nil {
				defer conn.Close()
			}
			if !errors.Is(err, dialErr) {
				t.Fatalf("UDP listen returned %v, want %v", err, dialErr)
			}
			if test.backupWorks {
				if history := group.udpHistory.LoadURLTestHistory(first.Tag()); history != firstProbe {
					t.Errorf("successful fallback changed the first exit's UDP probe to %v", history)
				}
				if history := group.udpHistory.LoadURLTestHistory(second.Tag()); history != secondProbe {
					t.Errorf("successful fallback changed the second exit's UDP probe to %v", history)
				}
				return
			}
			for _, exit := range []*udpProbeTestOutbound{first, second} {
				if history := group.udpHistory.LoadURLTestHistory(exit.Tag()); history != nil {
					t.Errorf("failed exit %q kept its UDP probe %v", exit.Tag(), history)
				}
			}
			if nested != nil && nested.group.udpHistory.LoadURLTestHistory(first.Tag()) != nil {
				t.Error("nested URLTest kept the failed exit's UDP probe")
			}
			nextConn, err := outbound.ListenPacket(t.Context(), destination)
			if err != nil {
				t.Fatalf("UDP listen on the alternate outbound failed: %v", err)
			}
			defer nextConn.Close()
			if selected := outbound.Selected(N.NetworkUDP); selected != alternate {
				t.Errorf("selected UDP outbound = %v, want alternate", selected)
			}
		})
	}
}

func TestURLTestKeepsUDPConnectionOpenedDuringTCPSwitch(t *testing.T) {
	first := &udpProbeTestOutbound{fallbackHealthTestOutbound: newFallbackHealthTestOutbound("first", true)}
	tcpOnly := newFallbackHealthTestOutbound("tcp-only", true)
	tcpOnly.Adapter = outboundAdapter.NewAdapter("test", tcpOnly.Tag(), []string{N.NetworkTCP}, nil)
	nextUDP := newFallbackHealthTestOutbound("next-udp", true)
	outbound := newDialTestURLTest(t, first, tcpOnly, nextUDP)
	group := outbound.group
	defer group.Close()

	attempts := 0
	first.beforeUDP = func(context.Context, M.Socksaddr) error {
		attempts++
		if attempts > 1 {
			return errors.New("unexpected UDP retry")
		}
		group.storeHistory(tcpOnly.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
		group.performUpdateCheck()
		return nil
	}
	packet, err := outbound.ListenPacket(t.Context(), M.ParseSocksaddr("192.0.2.1:51820"))
	if err != nil {
		t.Fatalf("UDP listen failed after %d attempt(s): %v", attempts, err)
	}
	defer packet.Close()
	if tcp, udp := outbound.Selected(N.NetworkTCP), outbound.Selected(N.NetworkUDP); tcp != tcpOnly || udp != first {
		t.Fatalf("unexpected selection: TCP = %v, UDP = %v", tcp, udp)
	}
	if err = packet.SetReadDeadline(time.Now()); err != nil {
		t.Fatalf("UDP connection did not survive the TCP switch: %v", err)
	}
	group.storeHistory(nextUDP.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	group.performUpdateCheck()
	if err = packet.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("UDP connection was not interrupted by the UDP switch: %v", err)
	}
}

func TestURLTestKeepsTheNewerUDPProbeResult(t *testing.T) {
	for _, olderFailed := range []bool{false, true} {
		t.Run(fmt.Sprintf("older_failed_%t", olderFailed), func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			member := &udpProbeTestOutbound{
				fallbackHealthTestOutbound: newFallbackHealthTestOutbound("exit", true),
				beforeUDP: func(ctx context.Context, _ M.Socksaddr) error {
					close(started)
					select {
					case <-release:
					case <-ctx.Done():
						return ctx.Err()
					}
					if olderFailed {
						return errors.New("UDP unavailable")
					}
					return nil
				},
			}
			replacement := &udpProbeTestOutbound{
				fallbackHealthTestOutbound: newFallbackHealthTestOutbound("exit", true),
				wrongReply:                 !olderFailed,
			}
			group := newDialTestURLTest(t, member).group
			enableTestUDPProbe(t, group)
			done := make(chan struct{})
			go func() {
				defer close(done)
				group.checkUDP(t.Context(), member.Tag(), member)
			}()
			<-started
			group.outbound.(*testOutboundManager).outbounds[member.Tag()] = replacement
			group.access.Lock()
			group.outbounds = []adapter.Outbound{replacement}
			group.access.Unlock()
			group.checkUDP(t.Context(), replacement.Tag(), replacement)
			_, tested := group.Select(N.NetworkUDP)
			close(release)
			<-done
			if tested != olderFailed {
				t.Fatalf("newer UDP probe tested = %t, want %t", tested, olderFailed)
			}
			if _, tested = group.Select(N.NetworkUDP); tested != olderFailed {
				t.Fatalf("older UDP probe changed tested to %t, want %t", tested, olderFailed)
			}
		})
	}
}

func TestURLTestProviderReplacementResetsProbeHistory(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		oldStarted, releaseOld := make(chan struct{}), make(chan struct{})
		newStarted, releaseNew := make(chan struct{}), make(chan struct{})
		old := &udpProbeTestOutbound{
			fallbackHealthTestOutbound: newFallbackHealthTestOutbound("provider/node", true),
			beforeUDP: func(context.Context, M.Socksaddr) error {
				close(oldStarted)
				<-releaseOld
				return nil
			},
		}
		replacement := &udpProbeTestOutbound{
			fallbackHealthTestOutbound: newFallbackHealthTestOutbound(old.Tag(), true),
			beforeUDP: func(context.Context, M.Socksaddr) error {
				close(newStarted)
				<-releaseNew
				return nil
			},
		}
		outbound := newDialTestURLTest(t, old)
		defer outbound.Close()
		provider := &testProvider{tag: "provider", outbounds: []adapter.Outbound{replacement}}
		outbound.providers = map[string]adapter.Provider{provider.Tag(): provider}
		outbound.providerTags = []string{provider.Tag()}
		outbound.outboundsCache = make(map[string][]adapter.Outbound)
		group := outbound.group
		enableTestUDPProbe(t, group)
		for _, delay := range []uint16{10, 20, 30} {
			time.Sleep(time.Millisecond)
			history := &adapter.URLTestHistory{Time: time.Now(), Delay: delay}
			group.storeHistory(old.Tag(), history)
			group.udpHistory.StoreURLTestHistory(old.Tag(), history)
		}
		oldDone := make(chan struct{})
		go func() {
			defer close(oldDone)
			group.checkUDP(t.Context(), old.Tag(), old)
		}()
		<-oldStarted
		outbound.outbound.(*testOutboundManager).outbounds[old.Tag()] = replacement
		if err := outbound.onProviderUpdated(provider.Tag()); err != nil {
			t.Fatal(err)
		}
		<-newStarted
		close(releaseOld)
		<-oldDone
		if history := group.udpHistory.LoadURLTestHistory(old.Tag()); history != nil {
			t.Errorf("UDP history before replacement probe finished = %v, want none", history)
		}
		close(releaseNew)
		synctest.Wait()
		for network, storage := range map[string]*urltest.HistoryStorage{N.NetworkTCP: group.history, N.NetworkUDP: group.udpHistory} {
			if delay, tested := storage.LoadDelay(replacement.Tag(), true); !tested || delay != 1 {
				t.Errorf("%s delay after first replacement probe = %d, tested = %t, want 1 and true", network, delay, tested)
			}
		}
	})
}

func TestURLTestCanceledTCPDialKeepsProbeResult(t *testing.T) {
	member := &fallbackBlockingOutbound{
		Adapter: outboundAdapter.NewAdapter(C.TypeVLESS, "blocking", []string{N.NetworkTCP}, nil),
		started: make(chan struct{}),
	}
	outbound := newDialTestURLTest(t, member)
	group := outbound.group
	measuredAt := group.history.LoadURLTestHistory(member.Tag()).Time
	for _, delay := range []uint16{40, 30, 50} {
		measuredAt = measuredAt.Add(time.Nanosecond)
		group.storeHistory(member.Tag(), &adapter.URLTestHistory{Time: measuredAt, Delay: delay})
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		select {
		case <-member.started:
			cancel()
		case <-ctx.Done():
		}
	}()
	if _, err := outbound.DialContext(ctx, N.NetworkTCP, M.Socksaddr{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("dial returned %v, want context.Canceled", err)
	}
	if delay, tested := group.history.LoadDelay(member.Tag(), true); !tested || delay != 40 {
		t.Fatalf("smoothed delay after canceled dial = %d, tested = %t, want 40 and true", delay, tested)
	}
	if raw := group.sharedHistory.LoadURLTestHistory(member.Tag()); raw == nil || raw.Delay != 50 {
		t.Fatalf("dashboard result after canceled dial = %v, want 50 ms", raw)
	}
}

func TestURLTestTCPFailureKeepsProbeUpdatedDuringDial(t *testing.T) {
	member := newFallbackHealthTestOutbound("member", true)
	outbound := newDialTestURLTest(t, member)
	group := outbound.group
	defer group.Close()
	old := group.history.LoadURLTestHistory(member.Tag())
	dialErr := errors.New("TCP dial failed")
	var fresh *adapter.URLTestHistory
	_, err := openURLTestConnection(t.Context(), outbound, N.NetworkTCP, func(ctx context.Context, _ adapter.Outbound) (net.Conn, error) {
		group.checkHTTPOutbounds(ctx, true)
		fresh = group.history.LoadURLTestHistory(member.Tag())
		return nil, dialErr
	}, (*interrupt.Group).NewConn)
	if !errors.Is(err, dialErr) {
		t.Fatalf("TCP dial returned %v, want %v", err, dialErr)
	}
	if fresh == nil || fresh == old {
		t.Fatal("TCP probe did not publish a fresh result")
	}
	if got := group.history.LoadURLTestHistory(member.Tag()); got != fresh {
		t.Errorf("local result after failed dial = %v, want %v", got, fresh)
	}
	if got := group.sharedHistory.LoadURLTestHistory(member.Tag()); got != fresh {
		t.Errorf("dashboard result after failed dial = %v, want %v", got, fresh)
	}
}

func TestURLTestCanceledUDPDialKeepsProbeResult(t *testing.T) {
	for _, network := range []string{"udp", "packet"} {
		t.Run(network, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			member := &udpProbeTestOutbound{
				fallbackHealthTestOutbound: newFallbackHealthTestOutbound("exit", true),
				beforeUDP: func(ctx context.Context, destination M.Socksaddr) error {
					if destination.Port == 51820 {
						cancel()
						return ctx.Err()
					}
					return nil
				},
			}
			outbound := newDialTestURLTest(t, member)
			enableTestUDPProbe(t, outbound.group)
			outbound.group.CheckOutbounds(t.Context(), true)
			destination := M.ParseSocksaddr("192.0.2.1:51820")
			var err error
			if network == "packet" {
				_, err = outbound.ListenPacket(ctx, destination)
			} else {
				_, err = outbound.DialContext(ctx, N.NetworkUDP, destination)
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("dial returned %v, want context.Canceled", err)
			}
			if _, tested := outbound.group.Select(N.NetworkUDP); !tested {
				t.Fatal("canceled dial invalidated the successful UDP probe")
			}
		})
	}
}

// A tunnel must not dial the first subscription member while its probe is
// stalled. It can use a tested member without waiting for that stalled probe.
func TestURLTestFirstConnectionWaitsForAWorkingMember(t *testing.T) {
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP, "packet", "probe"} {
		t.Run(network, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			blocked := &fallbackBlockingOutbound{
				Adapter: outboundAdapter.NewAdapter("test", "blocked", []string{N.NetworkTCP, N.NetworkUDP}, nil),
				started: make(chan struct{}),
			}
			working := &initialURLTestOutbound{newFallbackHealthTestOutbound("working", true)}
			manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{blocked.Tag(): blocked, working.Tag(): working}}
			logger := log.NewNOPFactory().NewLogger("test")
			group, err := NewURLTestGroup(ctx, manager, logger, []adapter.Outbound{blocked, working}, "http://health.test/generate_204", nil, 0, 0, 0, false)
			if err != nil {
				t.Fatal(err)
			}
			defer group.Close()
			urlTest := &URLTest{group: group}
			dialCtx, cancelDial := context.WithTimeout(ctx, time.Second)
			defer cancelDial()
			if network == "probe" {
				if _, err := urltest.URLTest(dialCtx, "http://health.test/", urlTest); err != nil {
					t.Fatal(err)
				}
				return
			}
			if network == "packet" {
				conn, err := urlTest.ListenPacket(dialCtx, M.Socksaddr{})
				if err != nil {
					t.Fatal(err)
				}
				conn.Close()
			} else {
				conn, err := urlTest.DialContext(dialCtx, network, M.Socksaddr{})
				if err != nil {
					t.Fatal(err)
				}
				conn.Close()
			}
		})
	}
}

func TestURLTestInitialSelectionCanBeCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	blocked := &fallbackBlockingOutbound{
		Adapter: outboundAdapter.NewAdapter("test", "blocked", []string{N.NetworkTCP}, nil),
		started: make(chan struct{}),
	}
	manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{blocked.Tag(): blocked}}
	group, err := NewURLTestGroup(ctx, manager, log.NewNOPFactory().NewLogger("test"), []adapter.Outbound{blocked}, "http://health.test/generate_204", nil, 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer group.Close()
	dialCtx, cancelDial := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancelDial()
	_, err = (&URLTest{group: group}).DialContext(dialCtx, N.NetworkTCP, M.Socksaddr{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestURLTestInitialSelectionWakesEveryWaitingConnection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	blocked := &fallbackBlockingOutbound{
		Adapter: outboundAdapter.NewAdapter("test", "blocked", []string{N.NetworkTCP}, nil),
		started: make(chan struct{}),
	}
	working := newFallbackHealthTestOutbound("working", true)
	manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{blocked.Tag(): blocked, working.Tag(): working}}
	group, err := NewURLTestGroup(ctx, manager, log.NewNOPFactory().NewLogger("test"), []adapter.Outbound{blocked, working}, "http://health.test/generate_204", nil, 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer group.Close()
	urlTest := &URLTest{group: group}
	results := make(chan error, 12)
	dialCtx, cancelDial := context.WithTimeout(ctx, time.Second)
	defer cancelDial()
	for range 12 {
		go func() {
			conn, err := urlTest.DialContext(dialCtx, N.NetworkTCP, M.Socksaddr{})
			if conn != nil {
				conn.Close()
			}
			results <- err
		}()
	}
	for range 12 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func TestURLTestInitialSelectionRejectsFailedMembers(t *testing.T) {
	node := newFallbackHealthTestOutbound("failed", false)
	manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{node.Tag(): node}}
	group, err := NewURLTestGroup(context.Background(), manager, log.NewNOPFactory().NewLogger("test"), []adapter.Outbound{node}, "http://health.test/generate_204", nil, 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer group.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = (&URLTest{group: group}).DialContext(ctx, N.NetworkTCP, M.Socksaddr{})
	if err == nil || !strings.Contains(err.Error(), "no outbound passed the initial URL test") {
		t.Fatalf("expected failed probes, got %v", err)
	}
	if node.dialCount != 1 {
		t.Fatalf("dialed a member after its probe failed: %d attempts", node.dialCount)
	}
}

func TestURLTestInitialSelectionRetriesAfterFailure(t *testing.T) {
	node := newFallbackHealthTestOutbound("node", false)
	manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{node.Tag(): node}}
	group, err := NewURLTestGroup(t.Context(), manager, log.NewNOPFactory().NewLogger("test"), []adapter.Outbound{node}, "http://health.test/", nil, 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	urlTest := &URLTest{group: group}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if conn, err := urlTest.DialContext(ctx, N.NetworkTCP, M.Socksaddr{}); err == nil {
		conn.Close()
		t.Fatal("expected the initial probe to fail")
	}
	node.setAvailable(true)
	conn, err := urlTest.DialContext(ctx, N.NetworkTCP, M.Socksaddr{})
	if err != nil {
		t.Fatalf("a recovered member was not retested: %v", err)
	}
	conn.Close()
}

type queuedURLTestOutbound struct {
	outboundAdapter.Adapter
	started *sync.WaitGroup
}

func (o *queuedURLTestOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	o.started.Done()
	<-ctx.Done()
	return nil, ctx.Err()
}

func (o *queuedURLTestOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not used")
}

type queuedURLTestManager struct {
	*testOutboundManager
	started *sync.WaitGroup
}

func (m *queuedURLTestManager) Outbound(tag string) (adapter.Outbound, bool) {
	if tag == "working" {
		m.started.Wait()
	}
	return m.testOutboundManager.Outbound(tag)
}

type delayedURLTestOutbound struct {
	*fallbackHealthTestOutbound
	delay time.Duration
}

func (o *delayedURLTestOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if destination.IsDomain() {
		select {
		case <-time.After(o.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return o.fallbackHealthTestOutbound.DialContext(ctx, network, destination)
}

func TestURLTestInitialSelectionWaitsForQueuedMembers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var started sync.WaitGroup
		started.Add(10)
		manager := &queuedURLTestManager{
			testOutboundManager: &testOutboundManager{outbounds: make(map[string]adapter.Outbound)},
			started:             &started,
		}
		var outbounds []adapter.Outbound
		for i := range 10 {
			node := &queuedURLTestOutbound{
				Adapter: outboundAdapter.NewAdapter("test", fmt.Sprint("blocked-", i), []string{N.NetworkTCP}, nil),
				started: &started,
			}
			outbounds = append(outbounds, node)
			manager.outbounds[node.Tag()] = node
		}
		working := &delayedURLTestOutbound{fallbackHealthTestOutbound: newFallbackHealthTestOutbound("working", true), delay: time.Millisecond}
		outbounds = append(outbounds, working)
		manager.outbounds[working.Tag()] = working
		group, err := NewURLTestGroup(ctx, manager, log.NewNOPFactory().NewLogger("test"), outbounds, "http://health.test/", nil, 0, 0, 0, false)
		if err != nil {
			t.Fatal(err)
		}
		dialCtx, cancelDial := context.WithTimeout(ctx, 3*C.TCPTimeout)
		defer cancelDial()
		conn, err := (&URLTest{group: group}).DialContext(dialCtx, N.NetworkTCP, M.Socksaddr{})
		if err != nil {
			t.Errorf("a healthy member queued behind ten stalled probes was not selected: %v", err)
		} else {
			conn.Close()
		}
		cancel()
		synctest.Wait()
	})
}

type bootstrapURLTestOutbound struct {
	*initialURLTestOutbound
	dns        *URLTest
	dnsNetwork string
}

func (o *bootstrapURLTestOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if destination.IsDomain() {
		ctx = adapter.ContextWithDNSTransportTag(ctx, "test-dns")
		var conn io.Closer
		var err error
		dnsServer := M.ParseSocksaddr("1.1.1.1:53")
		if o.dnsNetwork == "packet" {
			conn, err = o.dns.ListenPacket(ctx, dnsServer)
		} else {
			conn, err = o.dns.DialContext(ctx, o.dnsNetwork, dnsServer)
		}
		if err != nil {
			return nil, err
		}
		conn.Close()
		o.dns.group.access.RLock()
		ready := o.dns.group.initialTCPReady || o.dns.group.initialUDPReady
		o.dns.group.access.RUnlock()
		if ready {
			return nil, errors.New("bootstrap marked an untested member ready")
		}
	}
	return o.initialURLTestOutbound.DialContext(ctx, network, destination)
}

func TestURLTestInitialSelectionBootstrapsDNS(t *testing.T) {
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP, "packet"} {
		t.Run(network, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			blocked := &fallbackBlockingOutbound{
				Adapter: outboundAdapter.NewAdapter("test", "blocked", []string{N.NetworkTCP, N.NetworkUDP}, nil),
				started: make(chan struct{}),
			}
			working := &bootstrapURLTestOutbound{
				initialURLTestOutbound: &initialURLTestOutbound{newFallbackHealthTestOutbound("working", true)},
				dnsNetwork:             network,
			}
			manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{blocked.Tag(): blocked, working.Tag(): working}}
			group, err := NewURLTestGroup(ctx, manager, log.NewNOPFactory().NewLogger("test"), []adapter.Outbound{blocked, working}, "http://health.test/", nil, 0, 0, 0, false)
			if err != nil {
				t.Fatal(err)
			}
			urlTest := &URLTest{group: group}
			working.dns = urlTest
			dialCtx, cancelDial := context.WithTimeout(ctx, time.Second)
			defer cancelDial()
			conn, err := urlTest.DialContext(dialCtx, N.NetworkTCP, M.ParseSocksaddr("1.1.1.1:53"))
			if err != nil {
				t.Fatalf("DNS bootstrap through a healthy member failed: %v", err)
			}
			conn.Close()
		})
	}
}

func TestURLTestProbeLimits(t *testing.T) {
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		t.Run(network, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				manager := &testOutboundManager{outbounds: make(map[string]adapter.Outbound)}
				var options option.URLTestOutboundOptions
				for index := range 3 {
					tag := fmt.Sprint("stalled-", index)
					manager.outbounds[tag] = &fallbackBlockingOutbound{
						Adapter: outboundAdapter.NewAdapter("test", tag, []string{network}, nil),
						started: make(chan struct{}),
					}
					options.Outbounds = append(options.Outbounds, tag)
				}
				options.URL = "http://health.test/"
				options.Timeout = badoption.Duration(2 * time.Second)
				options.Concurrency = 2
				if network == N.NetworkUDP {
					options.UDPProbe = &option.URLTestUDPProbe{
						ServerOptions: option.ServerOptions{Server: "192.0.2.53"},
						Domain:        "health.test",
					}
				}
				ctx := service.ContextWith[adapter.OutboundManager](t.Context(), manager)
				outbound, err := NewURLTest(ctx, nil, log.NewNOPFactory().NewLogger("test"), "group", options)
				if err != nil {
					t.Fatal(err)
				}
				group := outbound.(*URLTest)
				if err = group.start(); err != nil {
					t.Fatal(err)
				}
				defer group.Close()
				started := time.Now()
				if network == N.NetworkTCP {
					group.group.checkHTTPOutbounds(ctx, true)
				} else {
					group.group.checkUDPOutbounds(ctx, true)
				}
				if elapsed := time.Since(started); elapsed != 4*time.Second {
					t.Fatalf("three probes with concurrency 2 and timeout 2s took %v, want 4s", elapsed)
				}
			})
		})
	}
}

func TestURLTestAppliesToleranceAfterFirstCompleteSweep(t *testing.T) {
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		t.Run(network, func(t *testing.T) {
			early := newTestOutbound("early")
			middle := newTestOutbound("middle")
			fastest := newTestOutbound("fastest")
			members := []adapter.Outbound{early, middle, fastest}
			group, err := NewURLTestGroup(
				t.Context(), nil, nil, members, "", nil, 0, 50, 0, false,
			)
			if err != nil {
				t.Fatal(err)
			}
			history := group.history
			if network == N.NetworkUDP {
				enableTestUDPProbe(t, group)
				history = group.udpHistory
			}
			measuredAt := time.Now()
			store := func(member adapter.Outbound, delay uint16) {
				measuredAt = measuredAt.Add(time.Second)
				history.StoreURLTestHistory(member.Tag(), &adapter.URLTestHistory{Time: measuredAt, Delay: delay})
			}
			outbound := &URLTest{group: group}
			assertSelected := func(want adapter.Outbound) {
				t.Helper()
				if got := outbound.Selected(network); got != want {
					t.Fatalf("selected %v, want %s", got, want.Tag())
				}
			}
			update := func(checked []adapter.Outbound) {
				var sweep *urlTestSweep
				if checked != nil {
					sweep = &urlTestSweep{outbounds: checked}
				}
				group.updateSelection(network == N.NetworkTCP, network == N.NetworkUDP, sweep)
			}

			store(early, 65)
			selection, err := group.selectForDial(t.Context(), network)
			if err != nil || selection.outbound != early {
				t.Fatalf("early dial selected %v, %v, want early", selection.outbound, err)
			}
			store(middle, 60)
			store(fastest, 90)
			store(fastest, 90)
			store(fastest, 54)
			update(nil)
			assertSelected(early)
			update(members)
			assertSelected(fastest)

			store(middle, 54)
			store(fastest, 104)
			update(members)
			assertSelected(fastest)

			store(fastest, 130)
			update(members)
			assertSelected(fastest)
			history.StoreURLTestHistory(fastest.Tag(), &adapter.URLTestHistory{Time: measuredAt, Delay: 130})
			update(members)
			assertSelected(fastest)

			store(fastest, 131)
			update(members)
			assertSelected(middle)

			history.DeleteURLTestHistory(middle.Tag())
			update(members)
			assertSelected(early)
		})
	}
}

func TestURLTestFirstSweepChecksTheCurrentNestedExit(t *testing.T) {
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		t.Run(network, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				stalled := &fallbackBlockingOutbound{
					Adapter: outboundAdapter.NewAdapter("test", "stalled", []string{network}, nil),
					started: make(chan struct{}),
				}
				fastest := &udpProbeTestOutbound{fallbackHealthTestOutbound: newFallbackHealthTestOutbound("fastest", true)}
				slowerBase := newFallbackHealthTestOutbound("slower", true)
				var slower adapter.Outbound = &delayedURLTestOutbound{fallbackHealthTestOutbound: slowerBase, delay: 20 * time.Millisecond}
				if network == N.NetworkUDP {
					slower = &udpProbeTestOutbound{
						fallbackHealthTestOutbound: slowerBase,
						beforeUDP: func(context.Context, M.Socksaddr) error {
							time.Sleep(20 * time.Millisecond)
							return nil
						},
					}
				}
				nestedGroup, err := NewURLTestGroup(
					t.Context(), nil, nil, []adapter.Outbound{stalled, fastest}, "", nil, 0, 0, 0, false,
				)
				if err != nil {
					t.Fatal(err)
				}
				defer nestedGroup.Close()
				nested := &URLTest{
					Adapter: outboundAdapter.NewAdapter(C.TypeURLTest, "nested", []string{network}, nil),
					group:   nestedGroup,
				}
				manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{
					stalled.Tag(): stalled, fastest.Tag(): fastest, slower.Tag(): slower, nested.Tag(): nested,
				}}
				group, err := NewURLTestGroup(
					t.Context(), manager, log.NewNOPFactory().NewLogger("test"),
					[]adapter.Outbound{nested, slower}, "http://health.test/", nil, 0, 50, 0, false,
				)
				if err != nil {
					t.Fatal(err)
				}
				defer group.Close()
				if network == N.NetworkUDP {
					enableTestUDPProbe(t, group)
				}
				check := func() {
					if network == N.NetworkTCP {
						group.checkHTTPOutbounds(t.Context(), true)
					} else {
						group.checkUDPOutbounds(t.Context(), true)
					}
				}
				firstSweepDone := make(chan struct{})
				go func() {
					check()
					close(firstSweepDone)
				}()
				<-stalled.started
				synctest.Wait()
				nestedGroup.storeHistory(fastest.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 1})
				nestedGroup.performUpdateCheck()
				<-firstSweepDone
				outbound := &URLTest{group: group}
				if selected := outbound.Selected(network); selected != slower {
					t.Fatalf("incomplete sweep selected %v, want slower", selected)
				}

				check()
				if selected := outbound.Selected(network); selected != nested {
					t.Fatalf("first complete sweep selected %v, want nested", selected)
				}
			})
		})
	}
}

// A tolerance near the uint16 limit means "keep the selected member"; a sum
// that wrapped around would read as a lower delay and switch to a slower one.
func TestURLTestToleranceDoesNotWrapAround(t *testing.T) {
	current := newTypedTestOutbound(C.TypeDirect, "current")
	slower := newTypedTestOutbound(C.TypeDirect, "slower")
	group, err := NewURLTestGroup(context.Background(), nil, nil, []adapter.Outbound{current, slower}, "", nil, 0, 65000, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	group.storeHistory(current.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 500})
	group.storeHistory(slower.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 1000})
	group.selectedOutboundTCP = current
	group.selectedOutboundUDP = current
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		if selected, ok := group.Select(network); selected != current || !ok {
			t.Fatalf("%s: selected %s instead of the current member", network, selected.Tag())
		}
	}
}

func TestURLTestGroupUsesExpectedStatus(t *testing.T) {
	node := newFallbackHealthTestOutbound("node", true)
	manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{node.Tag(): node}}
	rejected, err := urltest.ParseExpectedStatus("200")
	if err != nil {
		t.Fatal(err)
	}
	group, err := NewURLTestGroup(context.Background(), manager, log.NewNOPFactory().NewLogger("test"), []adapter.Outbound{node}, "http://health.test/generate_204", rejected, 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := group.URLTest(context.Background()); err != nil || len(result) != 0 {
		t.Fatalf("unexpected rejected result: %v, %v", result, err)
	}

	accepted, err := urltest.ParseExpectedStatus("204")
	if err != nil {
		t.Fatal(err)
	}
	group.expectedStatus = accepted
	if result, err := group.URLTest(context.Background()); err != nil || len(result) != 1 {
		t.Fatalf("unexpected accepted result: %v, %v", result, err)
	}
}

type urlTestProbeLogger struct {
	log.ContextLogger
	message string
	paused  chan<- struct{}
	release <-chan struct{}
}

func (l *urlTestProbeLogger) Debug(args ...any) {
	if strings.Contains(fmt.Sprint(args...), l.message) {
		close(l.paused)
		<-l.release
	}
}

func TestURLTestOlderTCPProbeFailureKeepsNewerSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		node := newFallbackHealthTestOutbound("node", false)
		manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{node.Tag(): node}}
		failed := make(chan struct{})
		release := make(chan struct{})
		logger := &urlTestProbeLogger{ContextLogger: log.NewNOPFactory().NewLogger("test"), message: " unavailable: ", paused: failed, release: release}
		group, err := NewURLTestGroup(
			t.Context(), manager, logger, []adapter.Outbound{node}, "http://health.test/", nil, 0, 0, 0, false,
		)
		if err != nil {
			t.Fatal(err)
		}
		defer group.Close()
		group.storeHistory(node.Tag(), &adapter.URLTestHistory{Time: time.Now().Add(-2 * time.Second), Delay: 25})
		group.storeHistory(node.Tag(), &adapter.URLTestHistory{Time: time.Now().Add(-time.Second), Delay: 30})

		olderSweepDone := make(chan struct{})
		go func() {
			defer close(olderSweepDone)
			group.checkHTTPOutbounds(t.Context(), true)
		}()
		<-failed
		node.setAvailable(true)
		time.Sleep(time.Millisecond)
		result := group.checkHTTPOutbounds(t.Context(), true)
		close(release)
		<-olderSweepDone

		if result[node.Tag()] != 1 {
			t.Fatalf("newer sweep returned %v, want 1 ms for %s", result, node.Tag())
		}
		if delay, tested := group.history.LoadDelay(node.Tag(), true); !tested || delay != 25 {
			t.Fatalf("smoothed delay after older failure = %d, tested = %t, want 25 and true", delay, tested)
		}
		if raw := group.sharedHistory.LoadURLTestHistory(node.Tag()); raw == nil || raw.Delay != 1 {
			t.Fatalf("dashboard result after older failure = %v, want 1 ms", raw)
		}
	})
}

func TestURLTestOlderTCPSuccessKeepsNewerFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		node := newFallbackHealthTestOutbound("node", true)
		manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{node.Tag(): node}}
		paused := make(chan struct{})
		release := make(chan struct{})
		logger := &urlTestProbeLogger{ContextLogger: log.NewNOPFactory().NewLogger("test"), message: " available: ", paused: paused, release: release}
		group, err := NewURLTestGroup(
			t.Context(), manager, logger, []adapter.Outbound{node}, "http://health.test/", nil, 0, 0, 0, false,
		)
		if err != nil {
			t.Fatal(err)
		}
		defer group.Close()
		olderSweepDone := make(chan struct{})
		go func() {
			defer close(olderSweepDone)
			group.checkHTTPOutbounds(t.Context(), true)
		}()
		<-paused
		node.setAvailable(false)
		time.Sleep(time.Millisecond)
		result := group.checkHTTPOutbounds(t.Context(), true)
		close(release)
		<-olderSweepDone

		if len(result) != 0 {
			t.Fatalf("newer failed sweep returned %v, want no delays", result)
		}
		if local := group.history.LoadURLTestHistory(node.Tag()); local != nil {
			t.Fatalf("local result after newer failure = %v, want no delay", local)
		}
		if raw := group.sharedHistory.LoadURLTestHistory(node.Tag()); raw != nil {
			t.Fatalf("dashboard result after newer failure = %v, want no delay", raw)
		}
	})
}

type urlTestWarningLogger struct {
	log.ContextLogger
	warnings int
}

func (l *urlTestWarningLogger) Warn(args ...any) { l.warnings++ }

func TestURLTestReportsAnUpdateThatLeftNoMembers(t *testing.T) {
	node := newTypedTestOutbound(C.TypeVLESS, "provider/node")
	manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{node.Tag(): node}}
	provider := &testProvider{tag: "provider", outbounds: []adapter.Outbound{node}}
	logger := &urlTestWarningLogger{ContextLogger: log.NewNOPFactory().NewLogger("test")}
	group, err := NewURLTestGroup(context.Background(), manager, logger, nil, "", nil, 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	urlTest := &URLTest{
		Adapter:        outboundAdapter.NewAdapter(C.TypeURLTest, "urltest", []string{"tcp", "udp"}, nil),
		ctx:            context.Background(),
		outbound:       manager,
		logger:         logger,
		group:          group,
		providers:      map[string]adapter.Provider{provider.Tag(): provider},
		outboundsCache: make(map[string][]adapter.Outbound),
		providerTags:   []string{provider.Tag()},
		include:        regexp.MustCompile("^nothing$"),
	}

	if err := urlTest.onProviderUpdated(provider.Tag()); err != nil {
		t.Fatal(err)
	}
	if all := urlTest.All(); len(all) != 0 {
		t.Fatalf("include filter kept an outbound it does not match: %v", all)
	}
	// The group stays up with nothing to select, so the reason has to be logged.
	if logger.warnings != 1 {
		t.Fatalf("unexpected warning count for an empty group: %d", logger.warnings)
	}

	urlTest.include = regexp.MustCompile("^node$")
	if err := urlTest.onProviderUpdated(provider.Tag()); err != nil {
		t.Fatal(err)
	}
	if all := urlTest.All(); len(all) != 1 || all[0] != node.Tag() {
		t.Fatalf("unexpected members after the filter started matching: %v", all)
	}
	if logger.warnings != 1 {
		t.Fatalf("a group that has members again still warned: %d", logger.warnings)
	}
}

// The result of the previous tick is a little younger than one interval when the
// next tick comes, so a tick that skips results younger than the interval tests
// each member only every other time.
func TestURLTestGroupTickRetestsTheResultOfThePreviousTick(t *testing.T) {
	node := newFallbackHealthTestOutbound("node", true)
	manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{node.Tag(): node}}
	group, err := NewURLTestGroup(context.Background(), manager, log.NewNOPFactory().NewLogger("test"), []adapter.Outbound{node}, "http://health.test/generate_204", nil, time.Minute, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	group.storeHistory(node.Tag(), &adapter.URLTestHistory{Time: time.Now().Add(-55 * time.Second), Delay: 10})
	group.CheckOutbounds(context.Background(), false)
	if node.dialCount != 1 {
		t.Fatalf("a tick skipped a member last tested by the previous tick: %d dials", node.dialCount)
	}
	group.CheckOutbounds(context.Background(), false)
	if node.dialCount != 1 {
		t.Fatalf("a tick retested a member it had just tested: %d dials", node.dialCount)
	}
}

// A scheduled check waits up to 15 s on a member that does not answer; a press
// on the dashboard has to measure the others within its own budget meanwhile.
func TestURLTestGroupPressDoesNotWaitForAScheduledCheck(t *testing.T) {
	slow := &fallbackBlockingOutbound{
		Adapter: outboundAdapter.NewAdapter("test", "slow", []string{"tcp"}, nil),
		started: make(chan struct{}),
	}
	fast := newFallbackHealthTestOutbound("fast", true)
	manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{slow.Tag(): slow, fast.Tag(): fast}}
	group, err := NewURLTestGroup(context.Background(), manager, log.NewNOPFactory().NewLogger("test"), []adapter.Outbound{slow, fast}, "http://health.test/generate_204", nil, 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	scheduled, cancelScheduled := context.WithCancel(context.Background())
	defer cancelScheduled()
	go group.CheckOutbounds(scheduled, false)
	<-slow.started
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	result, err := group.URLTest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, measured := result[fast.Tag()]; !measured {
		t.Fatalf("a press waiting for a scheduled check measured nothing: %v", result)
	}
}

// What a press measured before its budget ran out is applied: a selected member
// that just failed is replaced.
func TestURLTestGroupPressThatRanOutOfTimeStillSelects(t *testing.T) {
	first := newFallbackHealthTestOutbound("first", true)
	second := newFallbackHealthTestOutbound("second", true)
	slow := &fallbackBlockingOutbound{
		Adapter: outboundAdapter.NewAdapter("test", "slow", []string{"tcp"}, nil),
		started: make(chan struct{}),
	}
	manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{first.Tag(): first, second.Tag(): second, slow.Tag(): slow}}
	group, err := NewURLTestGroup(context.Background(), manager, log.NewNOPFactory().NewLogger("test"), []adapter.Outbound{first, second, slow}, "http://health.test/generate_204", nil, 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	group.storeHistory(first.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 100})
	group.storeHistory(second.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 300})
	group.performUpdateCheck()
	if selected, _ := group.Select(N.NetworkTCP); selected != first {
		t.Fatalf("unexpected initial selection: %v", selected.Tag())
	}
	first.setAvailable(false)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err = group.URLTest(ctx); err != nil {
		t.Fatal(err)
	}
	group.access.RLock()
	selected := group.selectedOutboundTCP
	group.access.RUnlock()
	if selected != second {
		t.Fatalf("a press that ran out of time kept a member that had just failed: %v", selected.Tag())
	}
}

// A forced check carries the API request's deadline; members it never reached keep their history.
func TestURLTestGroupKeepsHistoryOfMembersItCouldNotReach(t *testing.T) {
	node := &fallbackBlockingOutbound{
		Adapter: outboundAdapter.NewAdapter("test", "node", []string{"tcp"}, nil),
		started: make(chan struct{}),
	}
	manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{node.Tag(): node}}
	sharedHistory := urltest.NewHistoryStorage()
	ctx := service.ContextWithPtr(context.Background(), sharedHistory)
	group, err := NewURLTestGroup(
		ctx,
		manager,
		log.NewNOPFactory().NewLogger("test"),
		[]adapter.Outbound{node},
		"http://health.test/generate_204",
		nil, 0, 0, 0, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	group.storeHistory(node.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: 42})

	testCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := group.URLTest(testCtx); err != nil {
		t.Fatal(err)
	}

	if history := sharedHistory.LoadURLTestHistory(node.Tag()); history == nil || history.Delay != 42 {
		t.Fatalf("a check that ran out of time forgot a member it never finished testing: %v", history)
	}
}

type urlTestRefusingOutbound struct {
	outboundAdapter.Adapter
}

func (o *urlTestRefusingOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
}

func (o *urlTestRefusingOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not used")
}

// newDialTestURLTest selects the first member, which the URL tests found the fastest.
func newDialTestURLTest(t *testing.T, outbounds ...adapter.Outbound) *URLTest {
	t.Helper()
	manager := &testOutboundManager{outbounds: map[string]adapter.Outbound{}}
	for _, detour := range outbounds {
		manager.outbounds[detour.Tag()] = detour
	}
	logger := log.NewNOPFactory().NewLogger("test")
	group, err := NewURLTestGroup(context.Background(), manager, logger, outbounds, "http://health.test/generate_204", nil, time.Hour, 0, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	for index, detour := range outbounds {
		group.storeHistory(detour.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: uint16(100 * (index + 1))})
	}
	group.performUpdateCheck()
	if selected, _ := group.Select(N.NetworkTCP); selected != outbounds[0] {
		t.Fatalf("unexpected initial selection: %v", selected.Tag())
	}
	return &URLTest{
		Adapter:  outboundAdapter.NewAdapter(C.TypeURLTest, "urltest", []string{"tcp", "udp"}, nil),
		ctx:      context.Background(),
		outbound: manager,
		logger:   logger,
		group:    group,
	}
}

func waitForURLTestSelection(t *testing.T, urlTest *URLTest, want adapter.Outbound) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		urlTest.group.access.RLock()
		selected := urlTest.group.selectedOutboundTCP
		urlTest.group.access.RUnlock()
		if selected == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the group stayed on %s", selected.Tag())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A selected member whose dials fail is checked at the fifth failure, as Mihomo does, instead
// of failing every connection until the next periodic test.
func TestURLTestChecksAMemberWhoseDialsFail(t *testing.T) {
	first := newFallbackHealthTestOutbound("first", true)
	second := newFallbackHealthTestOutbound("second", true)
	urlTest := newDialTestURLTest(t, first, second)
	first.setAvailable(false)
	for attempt := 0; attempt < maxDialFailures; attempt++ {
		if attempt == maxDialFailures-1 && second.dialCount != 0 {
			t.Fatalf("the group checked its members before the fifth failure")
		}
		if _, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{}); err == nil {
			t.Fatal("a dial through an unavailable member succeeded")
		}
	}
	waitForURLTestSelection(t, urlTest, second)
}

func TestURLTestChecksAMemberThatRefusedAConnection(t *testing.T) {
	first := &urlTestRefusingOutbound{Adapter: outboundAdapter.NewAdapter(C.TypeVLESS, "first", []string{"tcp"}, nil)}
	second := newFallbackHealthTestOutbound("second", true)
	urlTest := newDialTestURLTest(t, first, second)
	if _, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{}); err == nil {
		t.Fatal("a refused dial succeeded")
	}
	waitForURLTestSelection(t, urlTest, second)
}

// A direct member cannot be down, and a dial the caller gave up says nothing of the member.
func TestURLTestCountsOnlyFailuresOfTheMember(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, test := range []struct {
		detour adapter.Outbound
		ctx    context.Context
	}{
		{&fallbackHealthTestOutbound{Adapter: outboundAdapter.NewAdapter(C.TypeDirect, "direct", []string{"tcp", "udp"}, nil)}, context.Background()},
		{&fallbackBlockingOutbound{Adapter: outboundAdapter.NewAdapter(C.TypeVLESS, "blocking", []string{"tcp"}, nil), started: make(chan struct{})}, canceled},
	} {
		urlTest := newDialTestURLTest(t, test.detour, newFallbackHealthTestOutbound("second", true))
		for attempt := 0; attempt < maxDialFailures-1; attempt++ {
			if _, err := urlTest.DialContext(test.ctx, N.NetworkTCP, M.Socksaddr{}); err == nil {
				t.Fatalf("%s: a dial succeeded", test.detour.Tag())
			}
		}
		if count := urlTest.group.failures.count; count != 0 {
			t.Errorf("%s: %d failures counted", test.detour.Tag(), count)
		}
	}
}

func TestURLTestStartsTheCountAgainAfterADial(t *testing.T) {
	first := newFallbackHealthTestOutbound("first", false)
	second := newFallbackHealthTestOutbound("second", true)
	urlTest := newDialTestURLTest(t, first, second)
	fail := func() {
		for attempt := 0; attempt < maxDialFailures-1; attempt++ {
			_, _ = urlTest.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
		}
	}
	fail()
	first.setAvailable(true)
	conn, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	first.setAvailable(false)
	fail()
	if count := urlTest.group.failures.count; count != maxDialFailures-1 || second.dialCount != 0 {
		t.Fatalf("a dial that went through did not start the count again: %d failures, %d checks", count, second.dialCount)
	}
}

type urlTestErrorLogger struct {
	log.ContextLogger
	errors int
}

func (l *urlTestErrorLogger) ErrorContext(context.Context, ...any) { l.errors++ }

// The connection manager logs a failed dial with the outbound it dialed, the group; the error
// names the member that failed, and the group logs nothing of its own.
func TestURLTestDialErrorNamesTheMember(t *testing.T) {
	first := newFallbackHealthTestOutbound("first", false)
	urlTest := newDialTestURLTest(t, first, newFallbackHealthTestOutbound("second", true))
	logger := &urlTestErrorLogger{ContextLogger: urlTest.logger}
	urlTest.logger = logger
	_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
	if err == nil || !strings.Contains(err.Error(), "outbound/test[first]") {
		t.Fatalf("the error does not name the member: %v", err)
	}
	_, err = urlTest.ListenPacket(context.Background(), M.Socksaddr{})
	if err == nil || !strings.Contains(err.Error(), "outbound/test[first]") {
		t.Fatalf("the error does not name the member: %v", err)
	}
	if logger.errors != 0 {
		t.Fatalf("the group logged the failure itself %d times", logger.errors)
	}
}
