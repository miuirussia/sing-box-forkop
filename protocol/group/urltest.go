package group

import (
	"context"
	"io"
	"maps"
	"net"
	"regexp"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

func RegisterURLTest(registry *outbound.Registry) {
	outbound.Register[option.URLTestOutboundOptions](registry, C.TypeURLTest, NewURLTest)
}

var (
	_ adapter.DialingOutboundGroup    = (*URLTest)(nil)
	_ adapter.InterfaceUpdateListener = (*URLTest)(nil)
)

type URLTest struct {
	outbound.Adapter
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	logger                       log.ContextLogger
	tags                         []string
	link                         string
	expectedStatus               urltest.ExpectedStatus
	udpProbe                     *urltest.UDPProbe
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	group                        *URLTestGroup
	checkAccess                  sync.Mutex
	interruptExternalConnections bool
	access                       sync.RWMutex

	provider          adapter.ProviderManager
	providers         map[string]adapter.Provider
	providerCallbacks []providerCallbackRegistration
	outboundsCache    map[string][]adapter.Outbound
	cancel            context.CancelFunc

	providerTags    []string
	exclude         *regexp.Regexp
	include         *regexp.Regexp
	excludeTypes    map[string]bool
	useAllProviders bool
}

func NewURLTest(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.URLTestOutboundOptions) (adapter.Outbound, error) {
	expectedStatus, err := urltest.ParseExpectedStatus(options.ExpectedStatus)
	if err != nil {
		return nil, E.Cause(err, "invalid URLTest expected_status")
	}
	var udpProbe *urltest.UDPProbe
	if options.UDPProbe != nil {
		udpProbe, err = urltest.NewUDPProbe(options.UDPProbe.Build(), options.UDPProbe.Domain)
		if err != nil {
			return nil, E.Cause(err, "invalid URLTest udp_probe")
		}
	}
	outbound := &URLTest{
		Adapter:                      outbound.NewAdapter(C.TypeURLTest, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		logger:                       logger,
		tags:                         options.Outbounds,
		link:                         options.URL,
		expectedStatus:               expectedStatus,
		udpProbe:                     udpProbe,
		interval:                     time.Duration(options.Interval),
		tolerance:                    options.Tolerance,
		idleTimeout:                  time.Duration(options.IdleTimeout),
		interruptExternalConnections: options.InterruptExistConnections,

		provider:       service.FromContext[adapter.ProviderManager](ctx),
		providers:      make(map[string]adapter.Provider),
		outboundsCache: make(map[string][]adapter.Outbound),

		providerTags:    options.Providers,
		exclude:         (*regexp.Regexp)(options.Exclude),
		include:         (*regexp.Regexp)(options.Include),
		excludeTypes:    excludedOutboundTypes(options.ExcludeTypes),
		useAllProviders: options.UseAllProviders,
	}
	for i, tag := range outbound.tags {
		if slices.Contains(outbound.tags[:i], tag) {
			return nil, E.New("duplicate tag: ", tag)
		}
	}
	return outbound, nil
}

func (s *URLTest) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateStart:
		scope.Add(s.Close)
		return s.start()
	case adapter.StartStateStarted:
		s.group.PostStart()
	}
	return nil
}

func (s *URLTest) start() (err error) {
	defer func() {
		if err != nil {
			unregisterProviderCallbacks(s.providerCallbacks)
			s.providerCallbacks = nil
		}
	}()
	if (s.useAllProviders || len(s.providerTags) > 0) && s.provider == nil {
		return E.New("outbound provider manager unavailable")
	}
	if s.useAllProviders {
		var providerTags []string
		for _, provider := range s.provider.Providers() {
			providerTags = append(providerTags, provider.Tag())
			s.providers[provider.Tag()] = provider
			s.providerCallbacks = append(s.providerCallbacks, registerProviderCallback(provider, s.onProviderUpdated))
		}
		s.providerTags = providerTags
	} else {
		for i, tag := range s.providerTags {
			provider, loaded := s.provider.Get(tag)
			if !loaded {
				return E.New("outbound provider ", i, " not found: ", tag)
			}
			s.providers[tag] = provider
			s.providerCallbacks = append(s.providerCallbacks, registerProviderCallback(provider, s.onProviderUpdated))
		}
	}
	if len(s.tags)+len(s.providerTags) == 0 {
		return E.New("missing outbound and provider tags")
	}

	outbounds := make([]adapter.Outbound, 0, len(s.tags))
	for i, tag := range s.tags {
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		outbounds = append(outbounds, detour)
	}
	group, err := NewURLTestGroup(s.ctx, s.outbound, s.logger, outbounds, s.link, s.expectedStatus, s.interval, s.tolerance, s.idleTimeout, s.interruptExternalConnections)
	if err != nil {
		return err
	}
	if s.udpProbe != nil {
		group.setUDPProbe(s.udpProbe)
	}
	s.group = group
	if len(s.providerTags) > 0 {
		return s.onProviderUpdated(s.providerTags[0])
	}
	return nil
}

func (s *URLTest) Close() error {
	s.access.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	s.access.Unlock()
	unregisterProviderCallbacks(s.providerCallbacks)
	s.providerCallbacks = nil
	return common.Close(
		common.PtrOrNil(s.group),
	)
}

func (s *URLTest) All() []string {
	s.access.RLock()
	defer s.access.RUnlock()
	return append([]string(nil), s.tags...)
}

func (s *URLTest) Selected(network string) adapter.Outbound {
	group := s.group
	if group == nil {
		return nil
	}
	var outbound adapter.Outbound
	group.access.RLock()
	if network == N.NetworkUDP {
		outbound = group.selectedOutboundUDP
	} else {
		outbound = group.selectedOutboundTCP
	}
	group.access.RUnlock()
	if outbound == nil {
		outbound, _ = group.Select(network)
	}
	return outbound
}

func (s *URLTest) AttachConnection(closer io.Closer) func() {
	return s.AttachConnectionForNetwork(N.NetworkTCP, closer)
}

func (s *URLTest) AttachConnectionForNetwork(network string, closer io.Closer) func() {
	s.group.Touch()
	return s.group.connectionsForNetwork(network).Add(closer, true)
}

// DialsMembers keeps the router dialing through the group, which counts the failed dials of its
// member and checks the group again at once when enough of them failed.
func (s *URLTest) DialsMembers() {}

func (s *URLTest) References() []string {
	group := s.group
	if group == nil {
		return nil
	}
	group.access.RLock()
	defer group.access.RUnlock()
	var references []string
	if group.selectedOutboundTCP != nil {
		references = append(references, group.selectedOutboundTCP.Tag())
	}
	if group.selectedOutboundUDP != nil && group.selectedOutboundUDP != group.selectedOutboundTCP {
		references = append(references, group.selectedOutboundUDP.Tag())
	}
	return references
}

func (s *URLTest) ProviderDependencies() []string {
	return providerDependencies(s.provider, s.providerTags, s.useAllProviders)
}

func (s *URLTest) URLTest(ctx context.Context) (map[string]uint16, error) {
	return s.group.URLTest(ctx)
}

func (s *URLTest) CheckOutbounds() {
	s.group.CheckOutbounds(s.ctx, true)
}

func (s *URLTest) PerformUpdateCheck() {
	s.group.performUpdateCheck()
}

func (s *URLTest) InterfaceUpdated(ctx context.Context) {
	group := s.group
	if group == nil {
		return
	}
	if group.pause.IsDevicePaused() || group.pause.IsNetworkPaused() {
		return
	}
	go func() {
		s.checkAccess.Lock()
		defer s.checkAccess.Unlock()
		if ctx.Err() != nil {
			return
		}
		group.CheckOutbounds(ctx, true)
	}()
}

func (s *URLTest) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	s.group.Touch()
	networkName := N.NetworkName(network)
	outbound, err := s.group.selectForDial(ctx, networkName)
	if err != nil {
		return nil, err
	}
	conn, err := outbound.DialContext(ctx, network, destination)
	if err == nil {
		s.group.dialSucceeded()
		return s.group.connectionsForNetwork(networkName).NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	s.group.deleteDialHistory(ctx, outbound, networkName)
	s.group.dialFailed(ctx, outbound, err)
	return nil, memberError(outbound, err)
}

// memberError names the member that failed: the caller logs the error with the outbound it
// dialed, which is the group or a selector above it.
func memberError(member adapter.Outbound, err error) error {
	return E.Cause(err, "outbound/", member.Type(), "[", member.Tag(), "]")
}

func (s *URLTest) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.group.Touch()
	outbound, err := s.group.selectForDial(ctx, N.NetworkUDP)
	if err != nil {
		return nil, err
	}
	conn, err := outbound.ListenPacket(ctx, destination)
	if err == nil {
		s.group.dialSucceeded()
		return s.group.connectionsForNetwork(N.NetworkUDP).NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	s.group.deleteDialHistory(ctx, outbound, N.NetworkUDP)
	s.group.dialFailed(ctx, outbound, err)
	return nil, memberError(outbound, err)
}

func (s *URLTest) onProviderUpdated(tag string) error {
	s.access.Lock()
	_, loaded := s.providers[tag]
	if !loaded {
		s.access.Unlock()
		return E.New("outbound provider not found: ", tag)
	}
	var (
		tags      = s.Dependencies()
		outbounds []adapter.Outbound
	)
	for _, tag := range tags {
		detour, _ := s.outbound.Outbound(tag)
		outbounds = append(outbounds, detour)
	}
	for _, providerTag := range s.providerTags {
		if providerTag != tag && s.outboundsCache[providerTag] != nil {
			for _, detour := range s.outboundsCache[providerTag] {
				tags = append(tags, detour.Tag())
				outbounds = append(outbounds, detour)
			}
			continue
		}
		provider := s.providers[providerTag]
		var cache []adapter.Outbound
		for _, detour := range provider.Outbounds() {
			tag := detour.Tag()
			filterTag := providerOutboundFilterTag(providerTag, tag)
			if s.excludeTypes[detour.Type()] {
				continue
			}
			if s.exclude != nil && s.exclude.MatchString(filterTag) {
				continue
			}
			if s.include != nil && !s.include.MatchString(filterTag) {
				continue
			}
			tags = append(tags, tag)
			cache = append(cache, detour)
		}
		outbounds = append(outbounds, cache...)
		s.outboundsCache[providerTag] = cache
	}
	if len(outbounds) == 0 {
		s.logger.Warn("urltest has no members, connections will fail until a member appears")
	}
	s.tags = tags
	s.group.access.Lock()
	s.group.outbounds = outbounds
	if s.group.selectedOutboundTCP != nil {
		s.group.selectedOutboundTCP = outboundByTag(outbounds, s.group.selectedOutboundTCP.Tag(), N.NetworkTCP)
	}
	if s.group.selectedOutboundUDP != nil {
		s.group.selectedOutboundUDP = outboundByTag(outbounds, s.group.selectedOutboundUDP.Tag(), N.NetworkUDP)
	}
	if s.group.ticker != nil {
		s.group.ticker.Reset(s.group.interval)
	}
	s.group.access.Unlock()
	ctx, cancel := context.WithCancel(s.ctx)
	if s.cancel != nil {
		s.cancel()
	}
	s.cancel = cancel
	s.access.Unlock()
	go s.group.CheckOutbounds(ctx, true)
	return nil
}

type URLTestGroup struct {
	ctx                          context.Context
	cancel                       context.CancelFunc
	outbound                     adapter.OutboundManager
	pause                        pause.Manager
	pauseCallback                *list.Element[pause.Callback]
	logger                       log.Logger
	outbounds                    []adapter.Outbound
	link                         string
	expectedStatus               urltest.ExpectedStatus
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	history                      *urltest.HistoryStorage
	udpHistory                   *urltest.HistoryStorage
	udpProbe                     *urltest.UDPProbe
	udpChecks                    map[string]*udpProbeChecks
	sharedHistory                *urltest.HistoryStorage
	coordinator                  *urltest.Coordinator
	checkingTCP                  atomic.Bool
	checkingUDP                  atomic.Bool
	refreshingUDP                atomic.Bool
	selectedOutboundTCP          adapter.Outbound
	selectedOutboundUDP          adapter.Outbound
	initialTCPReady              bool
	initialUDPReady              bool
	initialTCPCheckDone          chan struct{}
	initialUDPCheckDone          chan struct{}
	historyChanged               chan struct{}
	interruptGroup               *interrupt.Group
	udpInterruptGroup            *interrupt.Group
	interruptExternalConnections bool
	access                       sync.RWMutex
	ticker                       *time.Ticker
	started                      bool
	lastActive                   common.TypedValue[time.Time]
	failureAccess                sync.Mutex
	failures                     dialFailures
	failureCheck                 atomic.Bool
}

type udpProbeChecks struct {
	started uint64
	applied uint64
	active  int
}

func NewURLTestGroup(ctx context.Context, outboundManager adapter.OutboundManager, logger log.Logger, outbounds []adapter.Outbound, link string, expectedStatus urltest.ExpectedStatus, interval time.Duration, tolerance uint16, idleTimeout time.Duration, interruptExternalConnections bool) (*URLTestGroup, error) {
	if interval == 0 {
		interval = C.DefaultURLTestInterval
	}
	if tolerance == 0 {
		tolerance = 50
	}
	if idleTimeout == 0 {
		idleTimeout = C.DefaultURLTestIdleTimeout
	}
	if interval > idleTimeout {
		return nil, E.New("interval must be less or equal than idle_timeout")
	}
	coordinator := service.PtrFromContext[urltest.Coordinator](ctx)
	if coordinator == nil {
		coordinator = urltest.NewCoordinator()
	}
	groupCtx, cancel := context.WithCancel(ctx)
	return &URLTestGroup{
		ctx:                          groupCtx,
		cancel:                       cancel,
		outbound:                     outboundManager,
		logger:                       logger,
		outbounds:                    slices.Clone(outbounds),
		link:                         link,
		expectedStatus:               expectedStatus,
		interval:                     interval,
		tolerance:                    tolerance,
		idleTimeout:                  idleTimeout,
		history:                      urltest.NewHistoryStorage(),
		sharedHistory:                historyStorage(ctx),
		coordinator:                  coordinator,
		historyChanged:               make(chan struct{}),
		pause:                        service.FromContext[pause.Manager](ctx),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: interruptExternalConnections,
	}, nil
}

func (g *URLTestGroup) setUDPProbe(probe *urltest.UDPProbe) {
	g.udpProbe = probe
	g.udpHistory = urltest.NewHistoryStorage()
	g.udpChecks = make(map[string]*udpProbeChecks)
	g.udpInterruptGroup = interrupt.NewGroup()
}

func (g *URLTestGroup) connectionsForNetwork(network string) *interrupt.Group {
	if network == N.NetworkUDP && g.udpInterruptGroup != nil {
		return g.udpInterruptGroup
	}
	return g.interruptGroup
}

// freshFor is how long a scheduled check takes a result as current: half an interval keeps a tick
// from reusing the previous tick's results, while groups probing one member within it still share
// a probe.
func freshFor(interval time.Duration) time.Duration {
	return interval / 2
}

func (g *URLTestGroup) deleteHistory(tag string) {
	g.history.DeleteURLTestHistory(tag)
	g.sharedHistory.DeleteURLTestHistory(tag)
}

func (g *URLTestGroup) deleteDialHistory(ctx context.Context, detour adapter.Outbound, network string) {
	if network == N.NetworkUDP && g.udpHistory != nil {
		if ctx.Err() == nil {
			g.udpHistory.DeleteURLTestHistory(RealTag(detour, network))
		}
		return
	}
	g.deleteHistory(detour.Tag())
}

func (g *URLTestGroup) storeHistory(tag string, history *adapter.URLTestHistory) {
	g.history.StoreURLTestHistory(tag, history)
	g.sharedHistory.StoreURLTestHistory(tag, history)
	g.access.Lock()
	g.notifyHistoryChangedLocked()
	g.access.Unlock()
}

func (g *URLTestGroup) notifyHistoryChangedLocked() {
	close(g.historyChanged)
	g.historyChanged = make(chan struct{})
}

// The first dial needs a tested member. Wake on each successful probe so a
// tunnel does not wait for the slowest member of the initial batch.
func (g *URLTestGroup) selectForDial(ctx context.Context, network string) (adapter.Outbound, error) {
	dnsTransportTag, _ := adapter.DNSTransportTagFromContext(ctx)
	requiresUDPProbe := network == N.NetworkUDP && g.udpHistory != nil
	initialCheckDone := &g.initialTCPCheckDone
	if requiresUDPProbe {
		initialCheckDone = &g.initialUDPCheckDone
	}
	var checkDone <-chan struct{}
	finished := false
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		g.access.Lock()
		selected, ready := &g.selectedOutboundTCP, &g.initialTCPReady
		switch network {
		case N.NetworkTCP:
		case N.NetworkUDP:
			selected, ready = &g.selectedOutboundUDP, &g.initialUDPReady
		default:
			g.access.Unlock()
			return nil, E.Extend(N.ErrUnknownNetwork, network)
		}
		if *ready && *selected != nil && (!requiresUDPProbe || g.udpHistory.LoadURLTestHistory(RealTag(*selected, network)) != nil) {
			outbound := *selected
			g.access.Unlock()
			return outbound, nil
		}
		outbound, tested := g.selectOutbound(network)
		if outbound == nil {
			g.access.Unlock()
			return nil, E.New("missing supported outbound")
		}
		if tested || (*ready && !requiresUDPProbe) {
			udpChanged := requiresUDPProbe && *selected != nil && (*selected).Tag() != outbound.Tag()
			*selected, *ready = outbound, true
			g.access.Unlock()
			if udpChanged {
				g.udpInterruptGroup.Interrupt(g.interruptExternalConnections)
			}
			return outbound, nil
		}
		if probe := urltest.OutboundFromContext(ctx); probe != nil && dnsTransportTag != "" {
			// DNS for a probe may detour back through this group. Prefer the
			// member being probed, without declaring it tested yet.
			for _, member := range g.outbounds {
				if common.Contains(member.Network(), network) && MemberTag(member) == probe.Tag() {
					outbound = member
					break
				}
			}
			g.access.Unlock()
			return outbound, nil
		}
		if finished {
			g.access.Unlock()
			if requiresUDPProbe {
				return nil, E.New("no outbound passed the UDP probe")
			}
			return nil, E.New("no outbound passed the initial URL test for ", network)
		}
		if checkDone == nil {
			if *initialCheckDone == nil {
				done := make(chan struct{})
				*initialCheckDone = done
				go func() {
					if requiresUDPProbe {
						g.checkUDPOutbounds(g.ctx, true)
					} else {
						g.checkHTTPOutbounds(g.ctx, true)
					}
					g.access.Lock()
					*initialCheckDone = nil
					close(done)
					g.access.Unlock()
				}()
			}
			checkDone = *initialCheckDone
		}
		changed := g.historyChanged
		g.access.Unlock()
		select {
		case <-changed:
		case <-checkDone:
			finished = true
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-g.ctx.Done():
			return nil, g.ctx.Err()
		}
	}
}

func (g *URLTestGroup) dialSucceeded() {
	g.failureAccess.Lock()
	g.failures = dialFailures{}
	g.failureAccess.Unlock()
}

// dialFailed checks the members at once when failed dials call for it, instead of leaving the
// group on a dead member until the next periodic check; one such check runs at a time.
func (g *URLTestGroup) dialFailed(ctx context.Context, detour adapter.Outbound, err error) {
	if ctx.Err() != nil || !countableDialFailure(detour, err) {
		return
	}
	g.failureAccess.Lock()
	check := g.failures.add(time.Now(), err)
	g.failureAccess.Unlock()
	if !check || !g.failureCheck.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer g.failureCheck.Store(false)
		g.CheckOutbounds(g.ctx, true)
	}()
}

func (g *URLTestGroup) PostStart() {
	g.access.Lock()
	defer g.access.Unlock()
	g.started = true
	g.lastActive.Store(time.Now())
	go g.CheckOutbounds(g.ctx, false)
}

func (g *URLTestGroup) Touch() {
	g.access.Lock()
	defer g.access.Unlock()
	if !g.started || g.ctx.Err() != nil {
		return
	}
	if g.ticker != nil {
		g.lastActive.Store(time.Now())
		return
	}
	ticker := time.NewTicker(g.interval)
	g.ticker = ticker
	g.pauseCallback = pause.RegisterTicker(g.pause, ticker, g.interval, nil)
	go g.loopCheck(ticker)
}

func (g *URLTestGroup) Close() error {
	g.cancel()
	g.access.Lock()
	defer g.access.Unlock()
	if g.ticker == nil {
		return nil
	}
	g.ticker.Stop()
	g.ticker = nil
	g.pause.UnregisterCallback(g.pauseCallback)
	g.pauseCallback = nil
	return nil
}

func (g *URLTestGroup) Select(network string) (adapter.Outbound, bool) {
	g.access.RLock()
	defer g.access.RUnlock()
	return g.selectOutbound(network)
}

func (g *URLTestGroup) selectOutbound(network string) (adapter.Outbound, bool) {
	var minDelay uint16
	var minOutbound adapter.Outbound
	histories := g.history
	switch network {
	case N.NetworkTCP:
		if g.selectedOutboundTCP != nil {
			if history := g.history.LoadURLTestHistory(RealTag(g.selectedOutboundTCP, N.NetworkTCP)); history != nil {
				minOutbound = g.selectedOutboundTCP
				minDelay = history.Delay
			}
		}
	case N.NetworkUDP:
		if g.udpHistory != nil {
			histories = g.udpHistory
		}
		if g.selectedOutboundUDP != nil {
			if history := histories.LoadURLTestHistory(RealTag(g.selectedOutboundUDP, N.NetworkUDP)); history != nil {
				minOutbound = g.selectedOutboundUDP
				minDelay = history.Delay
			}
		}
	}
	for _, detour := range g.outbounds {
		if !common.Contains(detour.Network(), network) {
			continue
		}
		history := histories.LoadURLTestHistory(RealTag(detour, network))
		if history == nil {
			continue
		}
		if minDelay == 0 || uint32(minDelay) > uint32(history.Delay)+uint32(g.tolerance) {
			minDelay = history.Delay
			minOutbound = detour
		}
	}
	if minOutbound == nil {
		for _, detour := range g.outbounds {
			if !common.Contains(detour.Network(), network) {
				continue
			}
			return detour, false
		}
		return nil, false
	}
	return minOutbound, true
}

func (g *URLTestGroup) loopCheck(ticker *time.Ticker) {
	if time.Since(g.lastActive.Load()) > g.interval {
		g.lastActive.Store(time.Now())
		go g.CheckOutbounds(g.ctx, false)
	}
	for {
		select {
		case <-g.ctx.Done():
			return
		case <-ticker.C:
		}
		if time.Since(g.lastActive.Load()) > g.idleTimeout {
			g.access.Lock()
			if g.ticker == ticker {
				g.ticker.Stop()
				g.ticker = nil
				g.pause.UnregisterCallback(g.pauseCallback)
				g.pauseCallback = nil
			}
			g.access.Unlock()
			return
		}
		go g.CheckOutbounds(g.ctx, false)
	}
}

func (g *URLTestGroup) CheckOutbounds(ctx context.Context, force bool) {
	var udp sync.WaitGroup
	if g.udpProbe != nil {
		udp.Go(func() { g.checkUDPOutbounds(ctx, force) })
	}
	g.checkHTTPOutbounds(ctx, force)
	udp.Wait()
}

func (g *URLTestGroup) URLTest(ctx context.Context) (map[string]uint16, error) {
	g.refreshUDPInBackground(ctx, true)
	return g.checkHTTPOutbounds(ctx, true), nil
}

// Dashboard requests return HTTP delays. Refresh UDP using the group's
// lifetime so the dashboard request can return as soon as its results are ready.
func (g *URLTestGroup) refreshUDPInBackground(ctx context.Context, force bool) {
	if g.udpProbe == nil || ctx.Err() != nil || g.ctx.Err() != nil || !g.refreshingUDP.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer g.refreshingUDP.Store(false)
		g.checkUDPOutbounds(g.ctx, force)
	}()
}

func (g *URLTestGroup) snapshotOutbounds() []adapter.Outbound {
	g.access.RLock()
	defer g.access.RUnlock()
	// Writers replace the slice when a provider publishes its new members.
	return g.outbounds
}

func (g *URLTestGroup) checkHTTPOutbounds(ctx context.Context, force bool) map[string]uint16 {
	result := make(map[string]uint16)
	if !force {
		if !g.checkingTCP.CompareAndSwap(false, true) {
			return result
		}
		defer g.checkingTCP.Store(false)
	}
	maxAge := freshFor(g.interval)
	if force {
		maxAge = 0
	}
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	checked := make(map[string]bool)
	var resultAccess sync.Mutex
	for _, detour := range g.snapshotOutbounds() {
		tag := detour.Tag()
		realTag := MemberTag(detour)
		if checked[realTag] {
			continue
		}
		checked[realTag] = true
		p, loaded := g.outbound.Outbound(realTag)
		if !loaded {
			continue
		}
		history := g.history.LoadURLTestHistory(realTag)
		if !force && history != nil && time.Since(history.Time) < maxAge {
			continue
		}
		b.Go(realTag, func() (any, error) {
			t, at, err := g.coordinator.Check(ctx, g.link, g.expectedStatus, realTag, p, C.TCPTimeout, maxAge)
			if err != nil && ctx.Err() != nil {
				// Running out of the caller's time says nothing about the member,
				// so its history stays.
				return nil, nil
			}
			if err != nil {
				g.logger.Debug("outbound ", tag, " unavailable: ", err)
				g.deleteHistory(realTag)
			} else {
				g.logger.Debug("outbound ", tag, " available: ", t, "ms")
				g.storeHistory(realTag, &adapter.URLTestHistory{
					Time:  at,
					Delay: t,
				})
				resultAccess.Lock()
				result[tag] = t
				resultAccess.Unlock()
			}
			return nil, nil
		})
	}
	b.Wait()
	if g.ctx.Err() == nil {
		g.updateSelection(true, g.udpProbe == nil)
	}
	return result
}

func (g *URLTestGroup) checkUDPOutbounds(ctx context.Context, force bool) {
	if !force {
		if !g.checkingUDP.CompareAndSwap(false, true) {
			return
		}
		defer g.checkingUDP.Store(false)
	}
	maxAge := freshFor(g.interval)
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	checked := make(map[string]bool)
	for _, detour := range g.snapshotOutbounds() {
		if !common.Contains(detour.Network(), N.NetworkUDP) {
			continue
		}
		tag := RealTag(detour, N.NetworkUDP)
		if tag == "" || checked[tag] {
			continue
		}
		checked[tag] = true
		history := g.udpHistory.LoadURLTestHistory(tag)
		if !force && history != nil && time.Since(history.Time) < maxAge {
			continue
		}
		if outbound, loaded := g.outbound.Outbound(tag); loaded {
			b.Go(tag, func() (any, error) {
				g.checkUDP(ctx, tag, outbound)
				return nil, nil
			})
		}
	}
	b.Wait()
	if g.ctx.Err() == nil {
		g.updateSelection(false, true)
	}
}

func (g *URLTestGroup) checkUDP(ctx context.Context, tag string, detour adapter.Outbound) {
	if ctx.Err() != nil {
		return
	}
	g.access.Lock()
	checks := g.udpChecks[tag]
	if checks == nil {
		checks = new(udpProbeChecks)
		g.udpChecks[tag] = checks
	}
	checks.started++
	checks.active++
	sequence := checks.started
	g.access.Unlock()

	delay, at, err := g.coordinator.CheckUDP(ctx, g.udpProbe, tag, detour, C.TCPTimeout)
	g.access.Lock()
	defer g.access.Unlock()
	checks.active--
	if checks.active == 0 {
		delete(g.udpChecks, tag)
	}
	// A forced check can finish before an already running scheduled check.
	if ctx.Err() != nil || sequence < checks.applied {
		return
	}
	checks.applied = sequence
	if err != nil {
		g.udpHistory.DeleteURLTestHistory(tag)
		g.logger.Debug("UDP probe for ", tag, " failed: ", err)
		return
	}
	g.udpHistory.StoreURLTestHistory(tag, &adapter.URLTestHistory{Time: at, Delay: delay})
	g.notifyHistoryChangedLocked()
}

type urlTestResult struct {
	delay uint16
	err   error
}

type urlTestBatch struct {
	ctx      context.Context
	outbound adapter.OutboundManager
	history  *urltest.HistoryStorage
	logger   log.Logger
	batch    *batch.Batch[any]
	checked  map[string]bool
	groups   []adapter.OutboundGroup
	access   sync.Mutex
	result   map[string]uint16
}

func URLTestOutbounds(ctx context.Context, outboundManager adapter.OutboundManager, history *urltest.HistoryStorage, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, force bool) map[string]uint16 {
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	testBatch := &urlTestBatch{
		ctx:      ctx,
		outbound: outboundManager,
		history:  history,
		logger:   logger,
		batch:    b,
		checked:  make(map[string]bool),
		result:   make(map[string]uint16),
	}
	testBatch.test(outbounds, link, interval, force)
	b.Wait()
	for _, outboundGroup := range testBatch.groups {
		groupHistory := history.LoadURLTestHistory(RealTag(outboundGroup, N.NetworkTCP))
		if groupHistory != nil {
			testBatch.result[outboundGroup.Tag()] = groupHistory.Delay
		}
	}
	return testBatch.result
}

func (b *urlTestBatch) test(outbounds []adapter.Outbound, link string, interval time.Duration, force bool) {
	for _, detour := range outbounds {
		tag := detour.Tag()
		if b.checked[tag] {
			continue
		}
		switch nested := detour.(type) {
		case *URLTest:
			b.checked[tag] = true
			b.groups = append(b.groups, nested)
			b.batch.Go(tag, func() (any, error) {
				nested.group.refreshUDPInBackground(b.ctx, force)
				nestedResult := nested.group.checkHTTPOutbounds(b.ctx, force)
				b.access.Lock()
				maps.Copy(b.result, nestedResult)
				b.access.Unlock()
				return nil, nil
			})
		case adapter.OutboundGroup:
			b.checked[tag] = true
			b.groups = append(b.groups, nested)
			b.test(common.FilterNotNil(common.Map(nested.All(), func(it string) adapter.Outbound {
				member, _ := b.outbound.Outbound(it)
				return member
			})), link, interval, force)
		default:
			history := b.history.LoadURLTestHistory(tag)
			if !force && history != nil && time.Since(history.Time) < interval {
				continue
			}
			b.checked[tag] = true
			b.batch.Go(tag, func() (any, error) {
				testCtx, cancel := context.WithTimeout(b.ctx, C.TCPTimeout)
				defer cancel()
				testChan := make(chan urlTestResult, 1)
				go func() {
					delay, testErr := urltest.URLTest(testCtx, link, detour)
					testChan <- urlTestResult{delay, testErr}
				}()
				var testResult urlTestResult
				select {
				case testResult = <-testChan:
				case <-testCtx.Done():
					testResult.err = testCtx.Err()
				}
				if testResult.err != nil {
					b.logger.Debug("outbound ", tag, " unavailable: ", testResult.err)
					b.history.DeleteURLTestHistory(tag)
				} else {
					b.logger.Debug("outbound ", tag, " available: ", testResult.delay, "ms")
					b.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
						Time:  time.Now(),
						Delay: testResult.delay,
					})
					b.access.Lock()
					b.result[tag] = testResult.delay
					b.access.Unlock()
				}
				return nil, nil
			})
		}
	}
}

func (g *URLTestGroup) performUpdateCheck() {
	g.updateSelection(true, true)
}

func (g *URLTestGroup) updateSelection(tcp, udp bool) {
	g.access.Lock()
	var (
		tcpChanged bool
		udpChanged bool
		selected   bool
	)
	if tcp {
		if outbound, exists := g.selectOutbound(N.NetworkTCP); outbound != nil && (g.selectedOutboundTCP == nil || (exists && outbound != g.selectedOutboundTCP)) {
			tcpChanged = g.selectedOutboundTCP != nil && g.selectedOutboundTCP.Tag() != outbound.Tag()
			g.selectedOutboundTCP = outbound
			g.initialTCPReady = g.initialTCPReady || exists
			selected = true
		}
	}
	if udp {
		outbound, exists := g.selectOutbound(N.NetworkUDP)
		if g.udpProbe != nil && !exists {
			udpChanged = g.selectedOutboundUDP != nil
			g.selectedOutboundUDP = nil
			g.initialUDPReady = false
		} else if outbound != nil && (g.selectedOutboundUDP == nil || (exists && outbound != g.selectedOutboundUDP)) {
			udpChanged = g.selectedOutboundUDP != nil && g.selectedOutboundUDP.Tag() != outbound.Tag()
			g.selectedOutboundUDP = outbound
			g.initialUDPReady = g.initialUDPReady || exists
			selected = true
		}
	}
	g.access.Unlock()
	if tcpChanged || (udpChanged && g.udpInterruptGroup == nil) {
		g.interruptGroup.Interrupt(g.interruptExternalConnections)
	}
	if udpChanged && g.udpInterruptGroup != nil {
		g.udpInterruptGroup.Interrupt(g.interruptExternalConnections)
	}
	if selected {
		g.history.NotifyUpdated()
	}
}

func outboundByTag(outbounds []adapter.Outbound, tag string, network string) adapter.Outbound {
	if tag == "" {
		return nil
	}
	for _, outbound := range outbounds {
		if outbound.Tag() == tag && common.Contains(outbound.Network(), network) {
			return outbound
		}
	}
	return nil
}
