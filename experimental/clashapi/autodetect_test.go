package clashapi

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	outboundAdapter "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type autodetectOutbound struct {
	*linkAPIOutbound
	address     string
	fail        bool
	failFirst   bool
	failIPv6    bool
	destination M.Socksaddr
	calls       atomic.Int32
}

func (o *autodetectOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	count := o.calls.Add(1)
	o.destination = destination
	if o.fail || o.failFirst && count == 1 || o.failIPv6 && destination.Addr.Is6() {
		return nil, errors.New("connection reset by peer")
	}
	return (&net.Dialer{}).DialContext(ctx, network, o.address)
}

type autodetectDNSRouter struct {
	adapter.DNSRouter
	addresses []netip.Addr
	err       error
}

func (r *autodetectDNSRouter) Lookup(context.Context, string, adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return r.addresses, r.err
}

func addAutodetectTestConnection(t *testing.T, server *Server, outbound adapter.Outbound, metadata adapter.InboundContext) {
	t.Helper()
	client, other := net.Pipe()
	t.Cleanup(func() { other.Close() })
	metadata.Network = "tcp"
	metadata.OutboundChain = []adapter.Outbound{outbound}
	tracked := server.trafficManager.RoutedConnection(context.Background(), client, metadata, nil, outbound)
	if err := tracked.Close(); err != nil {
		t.Fatal(err)
	}
}

func newAutodetectOutbound(tag, address string, fail bool) *autodetectOutbound {
	return &autodetectOutbound{
		linkAPIOutbound: &linkAPIOutbound{Adapter: outboundAdapter.NewAdapter(C.TypeDirect, tag, []string{"tcp"}, nil)},
		address:         address,
		fail:            fail,
	}
}

func newTestAutodetector(t *testing.T, server *Server, options option.AutodetectOptions) *autodetector {
	t.Helper()
	detector, err := newAutodetector(server, options)
	if err != nil {
		t.Fatal(err)
	}
	return detector
}

func autodetectTestContext(server *httptest.Server) context.Context {
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	return service.ContextWith[adapter.CertificateStore](context.Background(), &exitTraceCertificateStore{pool: pool})
}

func TestAutodetectAPIAuthenticationAndDisabledState(t *testing.T) {
	t.Parallel()
	server, err := NewServer(clashTestContext(context.Background()), log.NewNOPFactory(), option.ClashAPIOptions{Secret: "test-secret"})
	if err != nil {
		t.Fatal(err)
	}
	handler := server.(*Server).httpServer.Handler
	request := httptest.NewRequest(http.MethodGet, "/autodetect", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unprotected endpoint: %d", response.Code)
	}
	request.Header.Set("Authorization", "Bearer test-secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var snapshot autodetectSnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if response.Code != 200 || snapshot.Enabled || snapshot.Results == nil || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected disabled state: %s", response.Body)
	}
}

func TestAutodetectDomain(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, domain string
		valid        bool
	}{
		{"site", "openwrt.org", true},
		{"punycode", "xn--e1afmkfd.xn--p1ai", true},
		{"local", "router.lan", false},
		{"literal IP", "127.0.0.1", false},
		{"URL", "https://openwrt.org/", false},
		{"empty label", "example..com", false},
		{"command", "example.com;id", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := autodetectDomain(test.domain); got != test.valid {
				t.Fatalf("domain validity = %v", got)
			}
		})
	}
}

func TestAutodetectVerdict(t *testing.T) {
	t.Parallel()
	ok := autodetectProbe{Status: 200}
	failure := autodetectProbe{Error: "TLS reset"}
	for _, test := range []struct {
		name          string
		direct, proxy autodetectProbe
		verdict       string
	}{
		{"working direct", ok, failure, "accessible"},
		{"direct reset and VPN works", failure, ok, "blocked"},
		{"both failed", failure, failure, "inconclusive"},
		{"server error", autodetectProbe{Status: 503}, ok, "inconclusive"},
		{"forbidden directly", autodetectProbe{Status: 403}, ok, "restricted"},
		{"forbidden everywhere", autodetectProbe{Status: 403}, autodetectProbe{Status: 403}, "inconclusive"},
		{"frozen body despite HTTP 200", autodetectProbe{Status: 200, Stage: "body", Error: "timeout"}, ok, "blocked"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := autodetectVerdict(test.direct, test.proxy); got != test.verdict {
				t.Fatalf("verdict = %s", got)
			}
		})
	}
}

func TestProbeAutodetectChecksSNIAndBoundedBody(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "GET" || r.Host != "example.com" || r.TLS.ServerName != "example.com" || r.Header.Get("Range") != "bytes=0-65535" {
			t.Errorf("unexpected request: %s Host=%s SNI=%s Range=%s", r.Method, r.Host, r.TLS.ServerName, r.Header.Get("Range"))
		}
		w.Write(make([]byte, 128*1024))
	}))
	defer site.Close()
	outbound := newAutodetectOutbound("vpn", site.Listener.Addr().String(), false)
	detector := newTestAutodetector(t, nil, option.AutodetectOptions{})
	result := detector.probe(autodetectTestContext(site), "example.com", M.ParseSocksaddr("203.0.113.1:443"), outbound)
	if result.Error != "" || result.Status != 200 || requests.Load() != 1 {
		t.Fatalf("probe: %+v", result)
	}
	if outbound.destination.String() != "203.0.113.1:443" {
		t.Fatal("did not preserve the observed IP")
	}
	result = detector.probe(autodetectTestContext(site), "openwrt.org", M.ParseSocksaddr("openwrt.org:443"), outbound)
	if result.Stage != "tls" || result.Error == "" {
		t.Fatalf("accepted another hostname's certificate: %+v", result)
	}
}

func TestProbeAutodetectDetectsFrozenBodyAndCancellation(t *testing.T) {
	t.Parallel()
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 16384))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer site.Close()
	outbound := newAutodetectOutbound("direct", site.Listener.Addr().String(), false)
	ctx, cancel := context.WithTimeout(autodetectTestContext(site), time.Second)
	defer cancel()
	detector := newTestAutodetector(t, nil, option.AutodetectOptions{})
	result := detector.probe(ctx, "example.com", M.ParseSocksaddr("example.com:443"), outbound)
	if result.Status != 200 || result.Stage != "body" || result.Error == "" {
		t.Fatalf("frozen response marked as reachable: %+v", result)
	}
}

func TestAutodetectConfirmsClosedConnectionWithoutChangingLatencyHistory(t *testing.T) {
	t.Parallel()
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer site.Close()
	ctx := autodetectTestContext(site)
	direct := newAutodetectOutbound("direct-out", "", true)
	proxy := newAutodetectOutbound("Main", site.Listener.Addr().String(), false)
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory("Main", &adapter.URLTestHistory{Time: time.Now(), Delay: 42})
	server := &Server{
		outbound:       &linkAPIOutboundManager{outbounds: []adapter.Outbound{direct, proxy}},
		trafficManager: trafficcontrol.NewManager(),
		urlTestHistory: history,
	}
	client, other := net.Pipe()
	defer other.Close()
	tracked := server.trafficManager.RoutedConnection(ctx, client, adapter.InboundContext{
		Network: "tcp", Domain: "example.com", Destination: M.ParseSocksaddr("203.0.113.1:443"),
		Source: M.ParseSocksaddr("192.168.1.2:1234"), OutboundChain: []adapter.Outbound{direct},
	}, nil, direct)
	tracked.Close()
	detector := newTestAutodetector(t, server, option.AutodetectOptions{
		Direct: "direct-out", Proxy: "Main", Confirmations: 3, RecheckInterval: badoption.Duration(time.Minute),
	})
	detector.step(ctx, time.Now())
	if len(detector.snapshot.Results) != 1 || detector.snapshot.Results[0].Verdict != "blocked" ||
		direct.calls.Load() != 3 || proxy.calls.Load() != 3 {
		t.Fatalf("did not confirm closed connection: %+v; calls=%d/%d", detector.snapshot, direct.calls.Load(), proxy.calls.Load())
	}
	detector.step(ctx, time.Now())
	if proxy.calls.Load() != 3 {
		t.Fatal("cooldown did not suppress a repeated check")
	}
	detector.step(ctx, time.Now().Add(90*time.Second))
	if proxy.calls.Load() != 6 {
		t.Fatal("configured recheck interval was ignored")
	}
	if history.LoadURLTestHistory("Main").Delay != 42 {
		t.Fatal("changed URLTest history")
	}
}

func TestAutodetectStallRequiresRepeatedUnchangedCounters(t *testing.T) {
	t.Parallel()
	now := time.Now()
	detector := newTestAutodetector(t, nil, option.AutodetectOptions{StallTimeout: badoption.Duration(15 * time.Second)})
	connection := &trafficcontrol.TrackerMetadata{Upload: new(atomic.Int64), Download: new(atomic.Int64)}
	connection.Upload.Store(1000)
	connection.Download.Store(16000)
	if detector.signal(connection, now) != "" || detector.signal(connection, now.Add(6*time.Second)) != "" {
		t.Fatal("one snapshot became a stall")
	}
	connection.Download.Add(1000)
	if detector.signal(connection, now.Add(9*time.Second)) != "" {
		t.Fatal("progress counted as a stall")
	}
	if detector.signal(connection, now.Add(18*time.Second)) != "" {
		t.Fatal("configured stall threshold was ignored")
	}
	if detector.signal(connection, now.Add(24*time.Second)) != "stalled" {
		t.Fatal("no stall after repeated observations")
	}
}

func TestAutodetectDoesNotConfirmTransientFailure(t *testing.T) {
	t.Parallel()
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer site.Close()
	ctx := autodetectTestContext(site)
	direct := newAutodetectOutbound("direct-out", site.Listener.Addr().String(), false)
	direct.failFirst = true
	proxy := newAutodetectOutbound("Main", site.Listener.Addr().String(), false)
	server := &Server{
		outbound:       &linkAPIOutboundManager{outbounds: []adapter.Outbound{direct, proxy}},
		trafficManager: trafficcontrol.NewManager(),
	}
	client, other := net.Pipe()
	defer other.Close()
	tracked := server.trafficManager.RoutedConnection(ctx, client, adapter.InboundContext{
		Network: "tcp", Domain: "example.com", Destination: M.ParseSocksaddr("203.0.113.1:443"),
		Source: M.ParseSocksaddr("192.168.1.2:1234"), OutboundChain: []adapter.Outbound{direct},
	}, nil, direct)
	tracked.Close()
	detector := newTestAutodetector(t, server, option.AutodetectOptions{Direct: "direct-out", Proxy: "Main"})
	detector.step(ctx, time.Now())
	if len(detector.snapshot.Results) != 1 || detector.snapshot.Results[0].Verdict != "inconclusive" {
		t.Fatalf("confirmed a one-off failure: %+v", detector.snapshot)
	}
}

func TestAutodetectCandidateSkipsOtherRoutesAndProtocols(t *testing.T) {
	t.Parallel()
	detector := newTestAutodetector(t, nil, option.AutodetectOptions{Direct: "direct-out"})
	now := time.Now()
	base := trafficcontrol.TrackerMetadata{
		CreatedAt: now.Add(-time.Minute), Chain: []string{"direct-out"}, Download: new(atomic.Int64),
		Metadata: adapter.InboundContext{Network: "tcp", Destination: M.ParseSocksaddr("openwrt.org:443")},
	}
	if detector.candidate(&base, now) != "openwrt.org" {
		t.Fatal("missed HTTPS domain")
	}
	for _, test := range []struct {
		name   string
		change func(*trafficcontrol.TrackerMetadata)
	}{
		{"VPN", func(c *trafficcontrol.TrackerMetadata) { c.Chain = []string{"vpn"} }},
		{"QUIC", func(c *trafficcontrol.TrackerMetadata) { c.Metadata.Network = "udp" }},
		{"unconfigured HTTPS port", func(c *trafficcontrol.TrackerMetadata) { c.Metadata.Destination.Port = 8443 }},
		{"local IP", func(c *trafficcontrol.TrackerMetadata) { c.Metadata.Destination = M.ParseSocksaddr("192.168.1.1:443") }},
		{"resolved local IP", func(c *trafficcontrol.TrackerMetadata) {
			c.Metadata.DestinationAddresses = []netip.Addr{netip.MustParseAddr("192.168.1.1")}
		}},
		{"mixed public and local IP", func(c *trafficcontrol.TrackerMetadata) {
			c.Metadata.DestinationAddresses = []netip.Addr{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("10.0.0.1")}
		}},
		{"fake IP", func(c *trafficcontrol.TrackerMetadata) { c.Metadata.Destination = M.ParseSocksaddr("198.18.0.1:443") }},
		{"expired", func(c *trafficcontrol.TrackerMetadata) { c.CreatedAt = now.Add(-time.Hour) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			connection := base
			test.change(&connection)
			if detector.candidate(&connection, now) != "" {
				t.Fatal("accepted excluded connection")
			}
		})
	}
}

func TestAutodetectDoesNotReportBlockedBeforeTestingFallback(t *testing.T) {
	t.Parallel()
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.ServerName != "example.com" {
			t.Errorf("incorrect SNI: %s", r.TLS.ServerName)
		}
		w.WriteHeader(204)
	}))
	defer site.Close()
	direct := &autodetectHangingOutbound{newAutodetectOutbound("direct", "", false)}
	proxy := newAutodetectOutbound("proxy", site.Listener.Addr().String(), false)
	detector := newTestAutodetector(t, nil, option.AutodetectOptions{Timeout: badoption.Duration(time.Second)})
	result := detector.probeTargets(autodetectTestContext(site), "example.com", []M.Socksaddr{
		M.ParseSocksaddr("203.0.113.1:443"), M.ParseSocksaddr("203.0.113.2:443"),
	}, direct, proxy)
	if result.Verdict != "inconclusive" {
		t.Fatalf("untested fallback marked as blocked: %+v", result)
	}
}

type autodetectHangingOutbound struct{ *autodetectOutbound }

func (o *autodetectHangingOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestAutodetectRejectsInvalidLimits(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		options option.AutodetectOptions
	}{
		{"timeout", option.AutodetectOptions{Timeout: badoption.Duration(61 * time.Second)}},
		{"confirmations", option.AutodetectOptions{Confirmations: 6}},
		{"stall threshold", option.AutodetectOptions{StallTimeout: badoption.Duration(2 * time.Second)}},
		{"body limit", option.AutodetectOptions{ResponseLimit: 1023}},
		{"recheck interval", option.AutodetectOptions{RecheckInterval: badoption.Duration(59 * time.Second)}},
		{"history limit", option.AutodetectOptions{HistoryLimit: 101}},
		{"zero port", option.AutodetectOptions{Ports: []uint16{0, 443}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newAutodetector(nil, test.options); err == nil {
				t.Fatal("accepted an unsafe limit")
			}
		})
	}
}

func TestAutodetectChecksConfiguredHTTPSPort(t *testing.T) {
	t.Parallel()
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com:8443" || r.TLS.ServerName != "example.com" {
			t.Errorf("incorrect HTTPS authority: Host=%s SNI=%s", r.Host, r.TLS.ServerName)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer site.Close()
	direct := newAutodetectOutbound("direct-out", "", true)
	proxy := newAutodetectOutbound("Main", site.Listener.Addr().String(), false)
	server := &Server{
		outbound:       &linkAPIOutboundManager{outbounds: []adapter.Outbound{direct, proxy}},
		trafficManager: trafficcontrol.NewManager(),
	}
	addAutodetectTestConnection(t, server, direct, adapter.InboundContext{
		Domain: "example.com", Destination: M.ParseSocksaddr("203.0.113.1:8443"),
	})
	detector := newTestAutodetector(t, server, option.AutodetectOptions{
		Direct: "direct-out", Proxy: "Main", Ports: []uint16{8443},
	})
	detector.step(autodetectTestContext(site), time.Now())
	if len(detector.snapshot.Results) != 1 {
		t.Fatalf("configured port was not checked: %+v", detector.snapshot)
	}
	result := detector.snapshot.Results[0]
	if result.Verdict != "blocked" || result.Target != "203.0.113.1:8443" ||
		direct.destination.Port != 8443 || proxy.destination.Port != 8443 ||
		direct.calls.Load() != 2 || proxy.calls.Load() != 2 {
		t.Fatalf("incorrect port or confirmation: %+v; calls=%d/%d", result, direct.calls.Load(), proxy.calls.Load())
	}
	addAutodetectTestConnection(t, server, direct, adapter.InboundContext{
		Domain: "example.com", Destination: M.ParseSocksaddr("203.0.113.1:443"),
	})
	detector.step(autodetectTestContext(site), time.Now())
	if direct.calls.Load() != 2 || proxy.calls.Load() != 2 {
		t.Fatal("checked port 443 even though only 8443 was configured")
	}
}

func TestAutodetectUsesConfiguredResponseLimit(t *testing.T) {
	t.Parallel()
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "bytes=0-1023" {
			t.Error("incorrect configured Range")
		}
		w.Write(make([]byte, 1024))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer site.Close()
	detector := newTestAutodetector(t, nil, option.AutodetectOptions{ResponseLimit: 1024, Timeout: badoption.Duration(time.Second)})
	outbound := newAutodetectOutbound("vpn", site.Listener.Addr().String(), false)
	result := detector.probe(autodetectTestContext(site), "example.com", M.ParseSocksaddr("example.com:443"), outbound)
	if result.Error != "" || result.Status != 200 {
		t.Fatalf("read past the configured limit: %+v", result)
	}
}

func TestAutodetectPreservesConfiguredPortsForResolvedTargets(t *testing.T) {
	t.Parallel()
	address := netip.MustParseAddr("203.0.113.1")
	server := &Server{dnsRouter: &autodetectDNSRouter{addresses: []netip.Addr{address}}}
	detector := newTestAutodetector(t, server, option.AutodetectOptions{
		Direct: "direct", Ports: []uint16{443, 8443, 65535},
	})
	for _, port := range detector.options.Ports {
		for _, source := range []string{"observed IP", "resolved addresses", "DNS lookup"} {
			t.Run(fmt.Sprintf("%s/%d", source, port), func(t *testing.T) {
				metadata := adapter.InboundContext{
					Network: "tcp", Domain: "example.com", Destination: M.Socksaddr{Fqdn: "example.com", Port: port},
				}
				switch source {
				case "observed IP":
					metadata.Destination = M.SocksaddrFrom(address, port)
				case "resolved addresses":
					metadata.DestinationAddresses = []netip.Addr{address, address}
				}
				connection := &trafficcontrol.TrackerMetadata{
					Metadata: metadata, Chain: []string{"direct"}, CreatedAt: time.Now().Add(-time.Minute),
				}
				if detector.candidate(connection, time.Now()) != "example.com" {
					t.Fatal("configured port was not accepted")
				}
				targets, err := detector.targets(context.Background(), connection, "example.com")
				if err != nil || len(targets) != 1 || targets[0] != M.SocksaddrFrom(address, port) {
					t.Fatalf("incorrect resolved target: %v, error: %v", targets, err)
				}
			})
		}
	}
}

func TestAutodetectUsesWorkingDNSFallback(t *testing.T) {
	t.Parallel()
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer site.Close()
	direct := newAutodetectOutbound("direct", site.Listener.Addr().String(), false)
	direct.failIPv6 = true
	proxy := newAutodetectOutbound("proxy", site.Listener.Addr().String(), false)
	server := &Server{
		outbound:       &linkAPIOutboundManager{outbounds: []adapter.Outbound{direct, proxy}},
		trafficManager: trafficcontrol.NewManager(),
	}
	addAutodetectTestConnection(t, server, direct, adapter.InboundContext{
		Destination:          M.ParseSocksaddr("example.com:443"),
		DestinationAddresses: []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("203.0.113.1")},
	})
	detector := newTestAutodetector(t, server, option.AutodetectOptions{Direct: "direct", Proxy: "proxy"})
	detector.step(autodetectTestContext(site), time.Now())
	if len(detector.snapshot.Results) != 1 || detector.snapshot.Results[0].Verdict != "accessible" {
		t.Fatalf("working IPv4 fallback classified as blocked: %+v", detector.snapshot)
	}
}

func TestAutodetectCooldownSurvivesHistoryEviction(t *testing.T) {
	t.Parallel()
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer site.Close()
	direct := newAutodetectOutbound("direct", site.Listener.Addr().String(), false)
	proxy := newAutodetectOutbound("proxy", site.Listener.Addr().String(), false)
	server := &Server{
		outbound:       &linkAPIOutboundManager{outbounds: []adapter.Outbound{direct, proxy}},
		trafficManager: trafficcontrol.NewManager(),
	}
	for i := 1; i <= 12; i++ {
		addAutodetectTestConnection(t, server, direct, adapter.InboundContext{
			Domain: "example.com", Destination: M.ParseSocksaddr(fmt.Sprintf("203.0.113.%d:443", i)),
		})
	}
	detector := newTestAutodetector(t, server, option.AutodetectOptions{Direct: "direct", Proxy: "proxy", HistoryLimit: 10})
	ctx := autodetectTestContext(site)
	seen := make(map[string]bool)
	for i := 0; i < 12; i++ {
		detector.step(ctx, time.Now())
		target := detector.snapshot.Results[0].Target
		if seen[target] {
			t.Fatalf("rechecked %s before cooldown; only %d of 12 targets checked", target, len(seen))
		}
		seen[target] = true
	}
	detector.step(ctx, time.Now())
	if direct.calls.Load() != 12 || proxy.calls.Load() != 12 || len(detector.snapshot.Results) != 10 {
		t.Fatalf("unexpected calls/history: %d/%d/%d", direct.calls.Load(), proxy.calls.Load(), len(detector.snapshot.Results))
	}
}

func TestAutodetectValidatesResolvedTargets(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		addresses []netip.Addr
		err       error
		probe     bool
	}{
		{"private", []netip.Addr{netip.MustParseAddr("192.168.1.1")}, nil, false},
		{"loopback", []netip.Addr{netip.MustParseAddr("::1")}, nil, false},
		{"mixed", []netip.Addr{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("10.0.0.1")}, nil, false},
		{"fakeip", []netip.Addr{netip.MustParseAddr("198.18.0.1")}, nil, false},
		{"empty", nil, nil, false},
		{"lookup error", nil, errors.New("DNS unavailable"), false},
		{"public", []netip.Addr{netip.MustParseAddr("203.0.113.1")}, nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
			defer site.Close()
			direct := newAutodetectOutbound("direct", site.Listener.Addr().String(), false)
			proxy := newAutodetectOutbound("proxy", site.Listener.Addr().String(), false)
			server := &Server{
				outbound:       &linkAPIOutboundManager{outbounds: []adapter.Outbound{direct, proxy}},
				trafficManager: trafficcontrol.NewManager(),
				dnsRouter:      &autodetectDNSRouter{addresses: test.addresses, err: test.err},
			}
			addAutodetectTestConnection(t, server, direct, adapter.InboundContext{Destination: M.ParseSocksaddr("example.com:443")})
			detector := newTestAutodetector(t, server, option.AutodetectOptions{Direct: "direct", Proxy: "proxy"})
			detector.step(autodetectTestContext(site), time.Now())
			if test.probe {
				if direct.calls.Load() != 1 || proxy.calls.Load() != 1 || !direct.destination.IsIP() || direct.destination != proxy.destination {
					t.Fatalf("public address was not pinned for both probes: %s/%s", direct.destination, proxy.destination)
				}
			} else if direct.calls.Load() != 0 || proxy.calls.Load() != 0 {
				t.Fatalf("unsafe destination probed: calls=%d/%d", direct.calls.Load(), proxy.calls.Load())
			}
		})
	}
}
