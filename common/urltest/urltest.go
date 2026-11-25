package urltest

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-mux"
	"github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/observable"
)

type HistoryStorage struct {
	access       sync.RWMutex
	delayHistory map[string]*adapter.URLTestHistory
	delaySamples map[string][3]uint16
	activeProbes map[string]activeHistoryProbes
	updateHooks  []*observable.Subscriber[struct{}]
}

type activeHistoryProbes struct {
	count      int
	lastFailed time.Time
}

func NewHistoryStorage() *HistoryStorage {
	return &HistoryStorage{
		delayHistory: make(map[string]*adapter.URLTestHistory),
	}
}

func NewHistoryStorageWithSmoothing() *HistoryStorage {
	storage := NewHistoryStorage()
	storage.delaySamples = make(map[string][3]uint16)
	return storage
}

func (s *HistoryStorage) AddUpdateHook(hook *observable.Subscriber[struct{}]) {
	s.access.Lock()
	defer s.access.Unlock()
	s.updateHooks = append(s.updateHooks, hook)
}

func (s *HistoryStorage) NotifyUpdated() {
	s.access.RLock()
	defer s.access.RUnlock()
	s.notifyUpdated()
}

func (s *HistoryStorage) LoadURLTestHistory(tag string) *adapter.URLTestHistory {
	if s == nil {
		return nil
	}
	s.access.RLock()
	defer s.access.RUnlock()
	return s.delayHistory[tag]
}

func (s *HistoryStorage) LoadDelay(tag string, smoothed bool) (uint16, bool) {
	s.access.RLock()
	defer s.access.RUnlock()
	history := s.delayHistory[tag]
	if history == nil {
		return 0, false
	}
	if samples := s.delaySamples[tag]; smoothed && samples[0] != 0 {
		slices.Sort(samples[:])
		return samples[1], true
	}
	return history.Delay, true
}

func (s *HistoryStorage) DeleteURLTestHistory(tag string) {
	s.access.Lock()
	defer s.access.Unlock()
	s.deleteURLTestHistoryLocked(tag)
}

// BeginProbe keeps failed observations until all overlapping probes can publish their results.
func (s *HistoryStorage) BeginProbe(tag string) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.activeProbes == nil {
		s.activeProbes = make(map[string]activeHistoryProbes)
	}
	probes := s.activeProbes[tag]
	probes.count++
	s.activeProbes[tag] = probes
}

func (s *HistoryStorage) EndProbe(tag string) {
	s.access.Lock()
	defer s.access.Unlock()
	probes := s.activeProbes[tag]
	probes.count--
	if probes.count == 0 {
		delete(s.activeProbes, tag)
	} else {
		s.activeProbes[tag] = probes
	}
}

// DeleteURLTestHistoryAt applies a failed probe unless a newer delay is stored.
func (s *HistoryStorage) DeleteURLTestHistoryAt(tag string, at time.Time) {
	s.access.Lock()
	defer s.access.Unlock()
	if probes, active := s.activeProbes[tag]; active && at.After(probes.lastFailed) {
		probes.lastFailed = at
		s.activeProbes[tag] = probes
	}
	if history := s.delayHistory[tag]; history != nil && !history.Time.After(at) {
		s.deleteURLTestHistoryLocked(tag)
	}
}

// DeleteURLTestHistoryIfCurrent deletes the result if history is still stored for tag.
func (s *HistoryStorage) DeleteURLTestHistoryIfCurrent(tag string, history *adapter.URLTestHistory) {
	s.access.Lock()
	defer s.access.Unlock()
	if history != nil && s.delayHistory[tag] == history {
		s.deleteURLTestHistoryLocked(tag)
	}
}

func (s *HistoryStorage) deleteURLTestHistoryLocked(tag string) {
	delete(s.delayHistory, tag)
	delete(s.delaySamples, tag)
	s.notifyUpdated()
}

func (s *HistoryStorage) StoreURLTestHistory(tag string, history *adapter.URLTestHistory) {
	s.access.Lock()
	defer s.access.Unlock()
	if history != nil {
		if failedAt := s.activeProbes[tag].lastFailed; !failedAt.IsZero() && !history.Time.After(failedAt) {
			return
		}
		previous := s.delayHistory[tag]
		if previous != nil && history.Time.Before(previous.Time) {
			return
		}
		if s.delaySamples != nil {
			// Several sweeps can receive the same result from the probe coordinator.
			if previous != nil && history.Time.Equal(previous.Time) {
				return
			}
			samples := s.delaySamples[tag]
			s.delaySamples[tag] = [3]uint16{samples[1], samples[2], history.Delay}
		}
	}
	s.delayHistory[tag] = history
	s.notifyUpdated()
}

func (s *HistoryStorage) notifyUpdated() {
	for _, updateHook := range s.updateHooks {
		updateHook.Emit(struct{}{})
	}
}

func (s *HistoryStorage) Close() error {
	s.access.Lock()
	defer s.access.Unlock()
	s.updateHooks = nil
	return nil
}

func URLTest(ctx context.Context, link string, detour N.Dialer) (uint16, error) {
	return URLTestWithExpectedStatus(ctx, link, detour, nil)
}

func URLTestWithExpectedStatus(ctx context.Context, link string, detour N.Dialer, expectedStatus ExpectedStatus) (uint16, error) {
	return urlTestWithTimeout(ctx, link, detour, expectedStatus, C.TCPTimeout)
}

func urlTestWithTimeout(ctx context.Context, link string, detour N.Dialer, expectedStatus ExpectedStatus, timeout time.Duration) (uint16, error) {
	ctx = context.WithValue(ctx, contextKeyOutbound{}, detour)
	multiplexOutbound, isMultiplexOutbound := common.Cast[adapter.OutboundWithMultiplex](detour)
	if isMultiplexOutbound && multiplexOutbound.MultiplexEnabled() {
		warmContext := adapter.ContextWithKeepSession(ctx)
		warmContext = mux.ContextWithKeepSession(warmContext)
		warmContext = contextWithQUICKeepSession(warmContext)
		warmContext = snell.ContextWithKeepSession(warmContext)
		_, err := urlTest(warmContext, link, detour, expectedStatus, timeout)
		if err != nil {
			return 0, err
		}
	}
	return urlTest(ctx, link, detour, expectedStatus, timeout)
}

func urlTest(ctx context.Context, link string, detour N.Dialer, expectedStatus ExpectedStatus, timeout time.Duration) (t uint16, err error) {
	if link == "" {
		link = "https://www.gstatic.com/generate_204"
	}
	linkURL, err := url.Parse(link)
	if err != nil {
		return
	}
	hostname := linkURL.Hostname()
	port := linkURL.Port()
	if port == "" {
		switch linkURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	start := time.Now()
	instance, err := detour.DialContext(ctx, "tcp", M.ParseSocksaddrHostPortStr(hostname, port))
	if err != nil {
		return
	}
	defer instance.Close()
	if N.NeedHandshakeForWrite(instance) {
		start = time.Now()
	}
	req, err := http.NewRequest(http.MethodHead, link, nil)
	if err != nil {
		return
	}
	var instanceTaken atomic.Bool
	client := http.Client{
		Transport: &http.Transport{
			// The transport dials with a context detached from the request's, so
			// a dial after the server closed the first connection takes the
			// probe's own, which ends with the probe.
			DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
				if !instanceTaken.Swap(true) {
					return instance, nil
				}
				return detour.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(ctx),
				RootCAs: adapter.RootPoolFromContext(ctx),
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: timeout,
	}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return
	}
	resp.Body.Close()
	if IsUnifiedDelayFromContext(ctx) {
		second := time.Now()
		trace := &httptrace.ClientTrace{
			GotConn: func(httptrace.GotConnInfo) { second = time.Now() },
		}
		resp, err = client.Do(req.WithContext(httptrace.WithClientTrace(ctx, trace)))
		if err != nil {
			return
		}
		resp.Body.Close()
		start = second
	}
	if !expectedStatus.Contains(uint16(resp.StatusCode)) {
		return 0, E.New("unexpected HTTP status: ", resp.StatusCode)
	}
	t = max(uint16(time.Since(start)/time.Millisecond), 1)
	return
}
