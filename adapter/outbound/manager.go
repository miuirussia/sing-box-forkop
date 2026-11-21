package outbound

import (
	"context"
	"os"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.OutboundManager = (*Manager)(nil)

type Manager struct {
	registry                adapter.OutboundRegistry
	endpoint                adapter.EndpointManager
	provider                adapter.ProviderManager
	defaultTag              string
	stageAccess             sync.Mutex
	access                  sync.RWMutex
	startAccess             sync.Mutex
	scope                   *adapter.Scope
	stage                   adapter.StartStage
	outbounds               []adapter.Outbound
	outboundByTag           map[string]adapter.Outbound
	dependByTag             map[string][]string
	defaultOutbound         adapter.Outbound
	defaultOutboundFallback func() (adapter.Outbound, error)
}

func NewManager(registry adapter.OutboundRegistry, endpoint adapter.EndpointManager, provider adapter.ProviderManager, defaultTag string) *Manager {
	return &Manager{
		registry:      registry,
		endpoint:      endpoint,
		provider:      provider,
		defaultTag:    defaultTag,
		outboundByTag: make(map[string]adapter.Outbound),
		dependByTag:   make(map[string][]string),
	}
}

func (m *Manager) Initialize(defaultOutboundFallback func() (adapter.Outbound, error)) {
	m.defaultOutboundFallback = defaultOutboundFallback
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.stageAccess.Lock()
	m.startAccess.Lock()
	outbounds, err := m.prepareStage(stage, scope)
	if err != nil || stage == adapter.StartStateStart {
		m.startAccess.Unlock()
		m.stageAccess.Unlock()
		if err != nil {
			return err
		}
		// Loading a subscription creates outbounds through WithStage. Do not hold
		// the stage or mutation locks while starting its dependencies.
		return m.startOutbounds(scope, append(outbounds, common.Map(m.endpoint.Endpoints(), func(it adapter.Endpoint) adapter.Outbound { return it })...))
	}
	defer m.stageAccess.Unlock()
	defer m.startAccess.Unlock()
	for _, outbound := range outbounds {
		lifecycle, isLifecycle := outbound.(adapter.Lifecycle)
		if !isLifecycle {
			continue
		}
		name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
		if err := scope.Start(name, lifecycle, stage); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) prepareStage(stage adapter.StartStage, scope *adapter.Scope) ([]adapter.Outbound, error) {
	m.access.Lock()
	m.scope = scope
	m.stage = stage
	if stage == adapter.StartStateInitialize {
		if m.defaultTag != "" && m.defaultOutbound == nil {
			defaultEndpoint, loaded := m.endpoint.Get(m.defaultTag)
			if !loaded {
				m.access.Unlock()
				return nil, E.New("default outbound not found: ", m.defaultTag)
			}
			m.defaultOutbound = defaultEndpoint
		}
		if m.defaultOutbound == nil {
			directOutbound, err := m.defaultOutboundFallback()
			if err != nil {
				m.access.Unlock()
				return nil, E.Cause(err, "create direct outbound for fallback")
			}
			m.outbounds = append(m.outbounds, directOutbound)
			m.outboundByTag[directOutbound.Tag()] = directOutbound
			m.defaultOutbound = directOutbound
		}
	}
	outbounds := append([]adapter.Outbound(nil), m.outbounds...)
	m.access.Unlock()
	return outbounds, nil
}

func (m *Manager) startOutbounds(scope *adapter.Scope, outbounds []adapter.Outbound) error {
	started := make(map[string]bool)
	initialized := make(map[string]bool)
	visiting := make(map[string]bool)
	var path []string
	var startOutbound func(string) error
	var startProvider func(adapter.Provider) error
	initializeOutbound := func(current adapter.Outbound) error {
		if initialized[current.Tag()] {
			return nil
		}
		if endpoint, ok := current.(adapter.Endpoint); ok {
			if err := m.endpoint.StartEndpoint(endpoint); err != nil {
				return err
			}
		} else if lifecycle, ok := current.(adapter.Lifecycle); ok {
			if err := scope.Start("outbound/"+current.Type()+"["+current.Tag()+"]", lifecycle, adapter.StartStateStart); err != nil {
				return err
			}
		}
		initialized[current.Tag()] = true
		return nil
	}
	start := func(key string, action func() error) error {
		if started[key] {
			return nil
		}
		if visiting[key] {
			return E.New("circular outbound/provider dependency: ", strings.Join(append(path, key), " -> "))
		}
		visiting[key] = true
		path = append(path, key)
		defer func() {
			delete(visiting, key)
			path = path[:len(path)-1]
		}()
		if err := action(); err != nil {
			return err
		}
		started[key] = true
		return nil
	}
	startProvider = func(provider adapter.Provider) error {
		return start("provider/"+provider.Tag(), func() error {
			if referrer, ok := provider.(adapter.Referrer); ok {
				for _, tag := range referrer.References() {
					if err := startOutbound(tag); err != nil {
						return err
					}
				}
			}
			return m.provider.StartProvider(provider)
		})
	}
	startOutbound = func(tag string) error {
		// A group can download its own subscription through a static or cached
		// member while the rest of its providers are still starting.
		if visiting["outbound/"+tag] && initialized[tag] {
			current, _ := m.Outbound(tag)
			if group, ok := current.(adapter.OutboundGroup); ok && group.Selected("tcp") != nil {
				return nil
			}
		}
		return start("outbound/"+tag, func() error {
			current, loaded := m.Outbound(tag)
			if !loaded {
				return E.New("outbound dependency not found: ", tag)
			}
			for _, dependency := range current.Dependencies() {
				if err := startOutbound(dependency); err != nil {
					return err
				}
			}
			if dependent, ok := current.(adapter.ProviderDependent); ok {
				var providers []adapter.Provider
				for _, providerTag := range dependent.ProviderDependencies() {
					provider, found := m.provider.Get(providerTag)
					if !found {
						return E.New("outbound provider not found: ", providerTag)
					}
					providers = append(providers, provider)
					for _, member := range provider.Outbounds() {
						if err := startOutbound(member.Tag()); err != nil {
							return err
						}
					}
				}
				if err := initializeOutbound(current); err != nil {
					return err
				}
				for _, provider := range providers {
					if err := startProvider(provider); err != nil {
						return err
					}
				}
			}
			return initializeOutbound(current)
		})
	}
	for _, current := range outbounds {
		if err := startOutbound(current.Tag()); err != nil {
			return err
		}
	}
	// Providers without a group still need to load and schedule updates.
	if m.provider != nil {
		for _, provider := range m.provider.Providers() {
			if err := startProvider(provider); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *Manager) Outbounds() []adapter.Outbound {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.outbounds
}

func (m *Manager) Outbound(tag string) (adapter.Outbound, bool) {
	m.access.RLock()
	outbound, found := m.outboundByTag[tag]
	m.access.RUnlock()
	if found {
		return outbound, true
	}
	return m.endpoint.Get(tag)
}

func (m *Manager) Default() adapter.Outbound {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.defaultOutbound
}

// WithStage holds the next start stage back while fn runs, so outbounds that fn
// starts in the scope through the stage it is given and swaps in run each stage
// exactly once. The scope is nil before the manager starts.
func (m *Manager) WithStage(fn func(stage adapter.StartStage, scope *adapter.Scope)) {
	m.stageAccess.Lock()
	defer m.stageAccess.Unlock()
	m.access.RLock()
	stage, scope := m.stage, m.scope
	m.access.RUnlock()
	fn(stage, scope)
}

func (m *Manager) SwapBatch(expectedOld map[string]adapter.Outbound, candidates []adapter.Outbound) (map[string]adapter.Outbound, error) {
	m.access.Lock()
	defer m.access.Unlock()
	removeSet := make(map[string]bool, len(expectedOld))
	for tag, expected := range expectedOld {
		if current := m.outboundByTag[tag]; current == nil || current != expected {
			return nil, E.New("outbound changed before batch swap: ", tag)
		}
		removeSet[tag] = true
	}
	candidateByTag := make(map[string]adapter.Outbound, len(candidates))
	for _, candidate := range candidates {
		tag := candidate.Tag()
		if tag == "" || candidateByTag[tag] != nil {
			return nil, E.New("invalid duplicate outbound candidate: ", tag)
		}
		if _, loaded := m.outboundByTag[tag]; loaded && !removeSet[tag] {
			return nil, E.New("outbound already exists: ", tag)
		}
		candidateByTag[tag] = candidate
	}
	for tag := range removeSet {
		for _, dependent := range m.dependByTag[tag] {
			if !removeSet[dependent] {
				return nil, E.New("outbound[", tag, "] is depended by ", dependent)
			}
		}
	}
	for _, candidate := range candidates {
		for _, dependency := range candidate.Dependencies() {
			if candidateByTag[dependency] != nil {
				continue
			}
			if _, loaded := m.outboundByTag[dependency]; loaded && !removeSet[dependency] {
				continue
			}
			if m.endpoint == nil {
				return nil, E.New("outbound dependency not found: ", dependency)
			}
			if _, loaded := m.endpoint.Get(dependency); !loaded {
				return nil, E.New("outbound dependency not found: ", dependency)
			}
		}
	}

	oldOutbounds := make(map[string]adapter.Outbound, len(expectedOld))
	for tag := range removeSet {
		oldOutbound := m.outboundByTag[tag]
		oldOutbounds[tag] = oldOutbound
		for _, dependency := range oldOutbound.Dependencies() {
			m.dependByTag[dependency] = common.Filter(m.dependByTag[dependency], func(it string) bool { return it != tag })
			if len(m.dependByTag[dependency]) == 0 {
				delete(m.dependByTag, dependency)
			}
		}
		delete(m.outboundByTag, tag)
	}
	remainingCandidates := make(map[string]adapter.Outbound, len(candidateByTag))
	for tag, candidate := range candidateByTag {
		remainingCandidates[tag] = candidate
	}
	updatedOutbounds := make([]adapter.Outbound, 0, len(m.outbounds)-len(removeSet)+len(candidates))
	for _, current := range m.outbounds {
		if !removeSet[current.Tag()] {
			updatedOutbounds = append(updatedOutbounds, current)
			continue
		}
		if candidate := remainingCandidates[current.Tag()]; candidate != nil {
			updatedOutbounds = append(updatedOutbounds, candidate)
			delete(remainingCandidates, current.Tag())
		}
	}
	for _, candidate := range candidates {
		if remainingCandidates[candidate.Tag()] != nil {
			updatedOutbounds = append(updatedOutbounds, candidate)
		}
		m.outboundByTag[candidate.Tag()] = candidate
		for _, dependency := range candidate.Dependencies() {
			m.dependByTag[dependency] = append(m.dependByTag[dependency], candidate.Tag())
		}
	}
	m.outbounds = updatedOutbounds
	if m.defaultOutbound != nil && removeSet[m.defaultOutbound.Tag()] {
		m.defaultOutbound = candidateByTag[m.defaultOutbound.Tag()]
	}
	if candidate := candidateByTag[m.defaultTag]; candidate != nil {
		m.defaultOutbound = candidate
	}
	if m.defaultOutbound == nil && len(m.outbounds) > 0 {
		m.defaultOutbound = m.outbounds[0]
	}
	return oldOutbounds, nil
}

func (m *Manager) Remove(tag string) error {
	m.startAccess.Lock()
	defer m.startAccess.Unlock()
	m.access.Lock()
	outbound, found := m.outboundByTag[tag]
	if !found {
		m.access.Unlock()
		return os.ErrInvalid
	}
	dependBy := m.dependByTag[tag]
	if len(dependBy) > 0 {
		m.access.Unlock()
		return E.New("outbound[", tag, "] is depended by ", strings.Join(dependBy, ", "))
	}
	delete(m.outboundByTag, tag)
	m.outbounds = common.Filter(m.outbounds, func(it adapter.Outbound) bool {
		return it != outbound
	})
	m.removeDependencies(outbound)
	if m.defaultOutbound == outbound {
		if len(m.outbounds) > 0 {
			m.defaultOutbound = m.outbounds[0]
		} else {
			m.defaultOutbound = nil
		}
	}
	scope := m.scope
	m.access.Unlock()
	lifecycle, isLifecycle := outbound.(adapter.Lifecycle)
	if scope == nil || !isLifecycle {
		return nil
	}
	return scope.Remove(lifecycle)
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, inboundType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}
	outbound, err := m.registry.CreateOutbound(ctx, router, logger, tag, inboundType, options)
	if err != nil {
		return err
	}
	m.startAccess.Lock()
	defer m.startAccess.Unlock()
	m.access.RLock()
	scope := m.scope
	stage := m.stage
	m.access.RUnlock()
	lifecycle, isLifecycle := outbound.(adapter.Lifecycle)
	if scope != nil && isLifecycle {
		name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
		for _, startStage := range adapter.ListStartStages[:stage+1] {
			err = scope.Start(name, lifecycle, startStage)
			if err != nil {
				return E.Errors(err, scope.Remove(lifecycle))
			}
		}
	}
	m.access.Lock()
	existsOutbound, loaded := m.outboundByTag[tag]
	if loaded {
		m.outbounds = common.Filter(m.outbounds, func(it adapter.Outbound) bool {
			return it != existsOutbound
		})
		m.removeDependencies(existsOutbound)
	}
	m.outbounds = append(m.outbounds, outbound)
	m.outboundByTag[tag] = outbound
	for _, dependency := range outbound.Dependencies() {
		m.dependByTag[dependency] = append(m.dependByTag[dependency], tag)
	}
	if tag == m.defaultTag || (m.defaultTag == "" && m.defaultOutbound == nil) || (loaded && m.defaultOutbound == existsOutbound) {
		m.defaultOutbound = outbound
	}
	m.access.Unlock()
	if !loaded || scope == nil {
		return nil
	}
	existsLifecycle, isExistsLifecycle := existsOutbound.(adapter.Lifecycle)
	if !isExistsLifecycle {
		return nil
	}
	err = scope.Remove(existsLifecycle)
	if err != nil {
		return E.Cause(err, "close outbound/", existsOutbound.Type(), "[", existsOutbound.Tag(), "]")
	}
	return nil
}

func (m *Manager) removeDependencies(outbound adapter.Outbound) {
	tag := outbound.Tag()
	for _, dependency := range outbound.Dependencies() {
		dependBy := common.Filter(m.dependByTag[dependency], func(it string) bool {
			return it != tag
		})
		if len(dependBy) == 0 {
			delete(m.dependByTag, dependency)
		} else {
			m.dependByTag[dependency] = dependBy
		}
	}
}
