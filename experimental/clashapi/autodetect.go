package clashapi

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"

	"github.com/go-chi/render"
	"github.com/gofrs/uuid/v5"
)

const autodetectCandidateMaxAge = 15 * time.Minute

type autodetectProbe struct {
	Status   int    `json:"status,omitempty"`
	Stage    string `json:"stage"`
	Error    string `json:"error,omitempty"`
	Duration int64  `json:"duration_ms"`
}

type autodetectResult struct {
	Domain    string          `json:"domain"`
	Target    string          `json:"target"`
	Source    string          `json:"source"`
	Verdict   string          `json:"verdict"`
	Signal    string          `json:"signal"`
	CheckedAt time.Time       `json:"checked_at"`
	Direct    autodetectProbe `json:"direct"`
	Proxy     autodetectProbe `json:"proxy"`
}

type autodetectSnapshot struct {
	Enabled  bool               `json:"enabled"`
	Proxy    string             `json:"proxy,omitempty"`
	Checking string             `json:"checking,omitempty"`
	Error    string             `json:"error,omitempty"`
	Results  []autodetectResult `json:"results"`
}

type autodetector struct {
	server       *Server
	options      option.AutodetectOptions
	access       sync.Mutex
	snapshot     autodetectSnapshot
	cancel       context.CancelFunc
	done         chan struct{}
	observations map[uuid.UUID]autodetectProgress
	checked      map[autodetectCheck]time.Time
}

type autodetectCheck struct {
	domain      string
	destination string
	addresses   string
}

type autodetectProgress struct {
	download  int64
	changedAt time.Time
	seenAt    time.Time
}

func newAutodetector(server *Server, options option.AutodetectOptions) (*autodetector, error) {
	if len(options.Ports) == 0 {
		options.Ports = []uint16{443}
	}
	if slices.Contains(options.Ports, 0) {
		return nil, fmt.Errorf("autodetect: ports must be between 1 and 65535")
	}
	for _, field := range []struct {
		name                   string
		value                  *badoption.Duration
		defaultValue, min, max time.Duration
	}{
		{"timeout", &options.Timeout, 8 * time.Second, time.Second, time.Minute},
		{"stall_timeout", &options.StallTimeout, 9 * time.Second, 3 * time.Second, 5 * time.Minute},
		{"recheck_interval", &options.RecheckInterval, 15 * time.Minute, time.Minute, 24 * time.Hour},
	} {
		if *field.value == 0 {
			*field.value = badoption.Duration(field.defaultValue)
		}
		if time.Duration(*field.value) < field.min || time.Duration(*field.value) > field.max {
			return nil, fmt.Errorf("autodetect: %s must be between %s and %s", field.name, field.min, field.max)
		}
	}
	for _, field := range []struct {
		name                   string
		value                  *int
		defaultValue, min, max int
	}{
		{"confirmations", &options.Confirmations, 2, 1, 5},
		{"response_limit", &options.ResponseLimit, 64 * 1024, 1024, 1024 * 1024},
		{"history_limit", &options.HistoryLimit, 100, 10, 100},
	} {
		if *field.value == 0 {
			*field.value = field.defaultValue
		}
		if *field.value < field.min || *field.value > field.max {
			return nil, fmt.Errorf("autodetect: %s must be between %d and %d", field.name, field.min, field.max)
		}
	}
	return &autodetector{
		server:       server,
		options:      options,
		observations: make(map[uuid.UUID]autodetectProgress),
		checked:      make(map[autodetectCheck]time.Time),
		snapshot:     autodetectSnapshot{Enabled: true, Proxy: options.Proxy, Results: []autodetectResult{}},
	}, nil
}

func (a *autodetector) start(ctx context.Context) {
	ctx, a.cancel = context.WithCancel(ctx)
	a.done = make(chan struct{})
	go func() {
		defer close(a.done)
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.step(ctx, time.Now())
			}
		}
	}()
}

func (a *autodetector) close() {
	if a.cancel != nil {
		a.cancel()
		<-a.done
	}
}

func (s *Server) getAutodetect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.autodetect == nil {
		render.JSON(w, r, autodetectSnapshot{Results: []autodetectResult{}})
		return
	}
	a := s.autodetect
	a.access.Lock()
	snapshot := a.snapshot
	snapshot.Results = slices.Clone(a.snapshot.Results)
	a.access.Unlock()
	snapshot.Results = slices.DeleteFunc(snapshot.Results, func(result autodetectResult) bool {
		return time.Since(result.CheckedAt) >= time.Duration(a.options.RecheckInterval)
	})
	render.JSON(w, r, snapshot)
}

// Trackers exist before the outbound dials. The closed list also holds quick TCP resets,
// which would be missed by a browser polling only the list of active connections.
func (a *autodetector) step(ctx context.Context, now time.Time) {
	direct, directOK := a.server.outbound.Outbound(a.options.Direct)
	proxy, proxyOK := a.server.outbound.Outbound(a.options.Proxy)
	if !directOK || !proxyOK || a.options.Direct == a.options.Proxy {
		a.access.Lock()
		a.snapshot.Error = "Autodetect requires distinct, available direct and proxy outbounds"
		a.access.Unlock()
		return
	}
	connections := append(a.server.trafficManager.Connections(), a.server.trafficManager.ClosedConnections()...)
	for id, progress := range a.observations {
		if now.Sub(progress.seenAt) > time.Minute {
			delete(a.observations, id)
		}
	}
	for key, checkedAt := range a.checked {
		if now.Sub(checkedAt) >= time.Duration(a.options.RecheckInterval) {
			delete(a.checked, key)
		}
	}
	// A busy router's recent failures get a turn before old closed connections.
	slices.SortFunc(connections, func(left, right *trafficcontrol.TrackerMetadata) int {
		return right.CreatedAt.Compare(left.CreatedAt)
	})
	for _, connection := range connections {
		domain := a.candidate(connection, now)
		if domain == "" {
			continue
		}
		signal := a.signal(connection, now)
		if signal == "" {
			continue
		}
		addresses := make([]string, len(connection.Metadata.DestinationAddresses))
		for i, address := range connection.Metadata.DestinationAddresses {
			addresses[i] = address.String()
		}
		slices.Sort(addresses)
		key := autodetectCheck{domain, connection.Metadata.Destination.String(), strings.Join(addresses, ",")}
		if _, recent := a.checked[key]; recent {
			continue
		}
		a.access.Lock()
		a.snapshot.Checking = domain
		a.snapshot.Error = ""
		a.access.Unlock()
		targets, err := a.targets(ctx, connection, domain)
		if len(targets) == 0 {
			a.access.Lock()
			a.snapshot.Checking = ""
			if err != nil {
				a.snapshot.Error = err.Error()
			}
			a.access.Unlock()
			if ctx.Err() == nil {
				a.checked[key] = time.Now()
			}
			return
		}
		result := a.probeTargets(ctx, domain, targets, direct, proxy)
		for attempt := 1; attempt < a.options.Confirmations &&
			(result.Verdict == "blocked" || result.Verdict == "restricted"); attempt++ {
			firstVerdict := result.Verdict
			result = a.probeTargets(ctx, domain, targets, direct, proxy)
			if firstVerdict != result.Verdict {
				result.Verdict = "inconclusive"
			}
		}
		result.Source = connection.Metadata.Source.Addr.String()
		result.Signal = signal
		result.CheckedAt = time.Now()
		a.access.Lock()
		a.snapshot.Checking = ""
		if ctx.Err() == nil {
			a.checked[key] = result.CheckedAt
			a.snapshot.Results = slices.DeleteFunc(a.snapshot.Results, func(old autodetectResult) bool {
				return old.Domain == domain && old.Target == result.Target
			})
			a.snapshot.Results = append([]autodetectResult{result}, a.snapshot.Results...)
			if len(a.snapshot.Results) > a.options.HistoryLimit {
				a.snapshot.Results = a.snapshot.Results[:a.options.HistoryLimit]
			}
		}
		a.access.Unlock()
		return // At most one domain per tick and two concurrent requests.
	}
}

func (a *autodetector) candidate(connection *trafficcontrol.TrackerMetadata, now time.Time) string {
	metadata := connection.Metadata
	if metadata.Network != N.NetworkTCP || !slices.Contains(a.options.Ports, metadata.Destination.Port) ||
		!slices.Contains(connection.Chain, a.options.Direct) ||
		now.Sub(connection.CreatedAt) > autodetectCandidateMaxAge ||
		(connection.ClosedAt.IsZero() && now.Sub(connection.CreatedAt) < 3*time.Second) {
		return ""
	}
	if metadata.Destination.Addr.IsValid() && !autodetectPublicAddress(metadata.Destination.Addr) {
		return ""
	}
	for _, address := range metadata.DestinationAddresses {
		if !autodetectPublicAddress(address) {
			return ""
		}
	}
	domain := metadata.Domain
	if domain == "" {
		domain = metadata.Destination.Fqdn
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if !autodetectDomain(domain) {
		return ""
	}
	return domain
}

// A completed response sitting on an idle keep-alive socket is harmless: the subsequent
// bounded HTTP request still has to reproduce the failure before any block is reported.
func (a *autodetector) signal(connection *trafficcontrol.TrackerMetadata, now time.Time) string {
	download := connection.Download.Load()
	if download < 1024 {
		if !connection.ClosedAt.IsZero() {
			return "early_close"
		}
		return "no_reply"
	}
	if !connection.ClosedAt.IsZero() || download > 128*1024 || connection.Upload.Load() == 0 {
		return ""
	}
	progress, loaded := a.observations[connection.ID]
	if !loaded || progress.download != download {
		if !loaded && len(a.observations) >= 512 {
			return ""
		}
		a.observations[connection.ID] = autodetectProgress{download: download, changedAt: now, seenAt: now}
		return ""
	}
	progress.seenAt = now
	a.observations[connection.ID] = progress
	if now.Sub(progress.changedAt) >= time.Duration(a.options.StallTimeout) {
		return "stalled"
	}
	return ""
}

func autodetectDomain(domain string) bool {
	if len(domain) > 253 || !strings.Contains(domain, ".") ||
		strings.HasSuffix(domain, ".local") || strings.HasSuffix(domain, ".lan") ||
		strings.HasSuffix(domain, ".home.arpa") {
		return false
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}

func autodetectPublicAddress(address netip.Addr) bool {
	address = address.Unmap()
	return address.IsGlobalUnicast() && !address.IsPrivate() &&
		!netip.MustParsePrefix("198.18.0.0/15").Contains(address)
}

// Resolve before either probe so internal names never reach the proxy and both paths
// use the same validated addresses. DNS answers are candidates, not the observed peer.
func (a *autodetector) targets(ctx context.Context, connection *trafficcontrol.TrackerMetadata, domain string) ([]M.Socksaddr, error) {
	metadata := connection.Metadata
	addresses := metadata.DestinationAddresses
	if metadata.Destination.IsIP() {
		addresses = []netip.Addr{metadata.Destination.Addr}
	}
	if len(addresses) == 0 {
		if a.server.dnsRouter == nil {
			return nil, fmt.Errorf("autodetect: missing DNS router")
		}
		ctx, cancel := context.WithTimeout(ctx, time.Duration(a.options.Timeout))
		defer cancel()
		var err error
		addresses, err = a.server.dnsRouter.Lookup(adapter.WithContext(ctx, &metadata), domain, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, fmt.Errorf("autodetect: resolve %s: %w", domain, err)
		}
	}
	targets := make([]M.Socksaddr, 0, len(addresses))
	for _, address := range addresses {
		if !autodetectPublicAddress(address) {
			return nil, nil
		}
		target := M.SocksaddrFrom(address.Unmap(), metadata.Destination.Port)
		if !slices.Contains(targets, target) {
			targets = append(targets, target)
		}
	}
	return targets, nil
}

func (a *autodetector) probeTargets(ctx context.Context, domain string, targets []M.Socksaddr, direct, proxy N.Dialer) autodetectResult {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(a.options.Timeout))
	defer cancel()
	var result autodetectResult
	for i, target := range targets {
		directResult, proxyResult := a.probePair(ctx, domain, target, direct, proxy)
		verdict := autodetectVerdict(directResult, proxyResult)
		if result.Verdict == "" || verdict != "inconclusive" {
			result = autodetectResult{Domain: domain, Target: target.String(), Direct: directResult, Proxy: proxyResult, Verdict: verdict}
		}
		if verdict == "accessible" {
			return result
		}
		// A timed-out first address says nothing about an untested fallback.
		if ctx.Err() != nil && i < len(targets)-1 {
			result.Verdict = "inconclusive"
			return result
		}
	}
	return result
}

func (a *autodetector) probePair(ctx context.Context, domain string, target M.Socksaddr, direct, proxy N.Dialer) (autodetectProbe, autodetectProbe) {
	var directResult, proxyResult autodetectProbe
	var tasks sync.WaitGroup
	tasks.Go(func() { directResult = a.probe(ctx, domain, target, direct) })
	tasks.Go(func() { proxyResult = a.probe(ctx, domain, target, proxy) })
	tasks.Wait()
	return directResult, proxyResult
}

// A bounded GET also catches a transfer frozen after a successful TLS handshake. It follows
// no redirects and never writes URLTest history or asks a group to change its selected member.
func (a *autodetector) probe(ctx context.Context, domain string, target M.Socksaddr, dialer N.Dialer) autodetectProbe {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(a.options.Timeout))
	defer cancel()
	start := time.Now()
	stage := "tcp"
	var stageAccess sync.Mutex
	setStage := func(value string) {
		stageAccess.Lock()
		stage = value
		stageAccess.Unlock()
	}
	transport := &http.Transport{
		DialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, target)
		},
		TLSClientConfig:        &tls.Config{Time: ntp.TimeFuncFromContext(ctx), RootCAs: adapter.RootPoolFromContext(ctx)},
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 32 * 1024,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		TLSHandshakeStart: func() { setStage("tls") },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				setStage("http")
			}
		},
	})
	authority := domain
	if target.Port != 443 {
		authority = net.JoinHostPort(domain, strconv.Itoa(int(target.Port)))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+authority+"/", nil)
	if err != nil {
		return autodetectProbe{Stage: "http", Error: err.Error()}
	}
	request.Header.Set("Range", "bytes=0-"+strconv.Itoa(a.options.ResponseLimit-1))
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(request)
	stageAccess.Lock()
	result := autodetectProbe{Stage: stage, Duration: time.Since(start).Milliseconds()}
	stageAccess.Unlock()
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer response.Body.Close()
	result.Stage = "http"
	result.Status = response.StatusCode
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		_, err = io.Copy(io.Discard, io.LimitReader(response.Body, int64(a.options.ResponseLimit)))
		if err != nil {
			result.Stage = "body"
			result.Error = err.Error()
		}
	}
	result.Duration = time.Since(start).Milliseconds()
	return result
}

func autodetectVerdict(direct, proxy autodetectProbe) string {
	success := func(probe autodetectProbe) bool {
		return probe.Error == "" && probe.Status >= 200 && probe.Status < 400
	}
	if success(direct) {
		return "accessible"
	}
	if success(proxy) {
		if direct.Error != "" {
			return "blocked"
		}
		if direct.Status == http.StatusForbidden || direct.Status == http.StatusUnavailableForLegalReasons {
			return "restricted"
		}
	}
	return "inconclusive"
}
