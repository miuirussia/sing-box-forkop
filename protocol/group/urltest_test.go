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
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

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
	second.deleteHistory("node")

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
}

func (o *delayedURLTestOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if destination.IsDomain() {
		select {
		case <-time.After(time.Millisecond):
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
		working := &delayedURLTestOutbound{newFallbackHealthTestOutbound("working", true)}
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
