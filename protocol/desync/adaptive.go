package desync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/publicsuffix"
)

// Store is optional; without cache.db Adaptive continues learning in memory.
type Store interface {
	LoadDesync(string) ([]byte, error)
	StoreDesync(string, []byte) error
	ClearDesync(string) error
}
type Score struct {
	Success    uint64  `json:"success"`
	Failure    uint64  `json:"failure"`
	LatencyMS  float64 `json:"latency_ms"`
	LastReason string  `json:"last_reason"`
}
type Entry struct {
	Updated    time.Time        `json:"updated"`
	Strategies map[string]Score `json:"strategies"`
	Hosts      []string         `json:"hosts,omitempty"`
}
type Snapshot struct {
	RouteGeneration  uint64            `json:"route_generation,omitempty"`
	PersistenceError string            `json:"persistence_error,omitempty"`
	LastSwitch       string            `json:"last_switch,omitempty"`
	Version          int               `json:"version"`
	Partition        string            `json:"partition"`
	Entries          map[string]*Entry `json:"entries"`
	Active           int               `json:"active"`
	Current          string            `json:"current,omitempty"`
	Reason           string            `json:"reason,omitempty"`
}
type Adaptive struct {
	routeGeneration              uint64
	persistenceError, lastSwitch string
	persistMu                    sync.Mutex
	mu                           sync.Mutex
	options                      option.DesyncOptions
	catalog                      []option.DesyncOptions
	partition                    string
	entries                      map[string]*Entry
	active                       map[string]int
	total                        int
	current, reason              string
	store                        Store
	timer                        *time.Timer
	closed                       bool
}

func NewAdaptive(tag string, o option.DesyncOptions) *Adaptive {
	data, _ := json.Marshal(o)
	sum := sha256.Sum256(append([]byte(tag+"\x00"), data...))
	a := &Adaptive{
		options: cloneDesyncOptions(o), partition: hex.EncodeToString(sum[:16]),
		entries: map[string]*Entry{}, active: map[string]int{}, catalog: adaptiveCatalog(o),
	}
	return a
}
func (a *Adaptive) Load() error {
	if a.store == nil {
		return nil
	}
	data, err := a.store.LoadDesync(a.partition)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	if len(data) > 16<<20 {
		return fmt.Errorf("desync cache snapshot exceeds 16 MiB")
	}
	var s Snapshot
	if json.Unmarshal(data, &s) != nil || s.Version != 1 || s.Partition != a.partition {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.routeGeneration += s.RouteGeneration
	now := time.Now()
	known := make(map[string]bool, len(a.catalog))
	for _, candidate := range a.catalog {
		known[strategyID(candidate)] = true
	}
	for key, e := range s.Entries {
		if e == nil || e.Strategies == nil || len(e.Strategies) > maxAdaptiveStrategies || e.Updated.After(now) || now.Sub(e.Updated) > time.Duration(a.options.Adaptive.TTL) {
			continue
		}
		// Version 1 snapshots may contain mode-only keys. They cannot be
		// attributed to a full configuration, so retain only exact known IDs.
		for id := range e.Strategies {
			if !known[id] {
				delete(e.Strategies, id)
			}
		}
		if len(e.Strategies) == 0 {
			continue
		}
		a.entries[key] = e
		if len(a.entries) >= a.options.Adaptive.MaxEntries {
			break
		}
	}
	a.pruneLocked(now)
	return nil
}
func (a *Adaptive) Stats() Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneLocked(time.Now())
	return a.snapshotLocked()
}
func (a *Adaptive) snapshotLocked() Snapshot {
	s := Snapshot{RouteGeneration: a.routeGeneration, Version: 1, Partition: a.partition, Entries: make(map[string]*Entry, len(a.entries)), Active: a.total, Current: a.current, Reason: a.reason, PersistenceError: a.persistenceError, LastSwitch: a.lastSwitch}
	for k, e := range a.entries {
		copyEntry := &Entry{Updated: e.Updated, Strategies: make(map[string]Score, len(e.Strategies)), Hosts: append([]string(nil), e.Hosts...)}
		for name, score := range e.Strategies {
			copyEntry.Strategies[name] = score
		}
		s.Entries[k] = copyEntry
	}
	return s
}
func (a *Adaptive) Flush() error {
	a.persistMu.Lock()
	defer a.persistMu.Unlock()
	a.mu.Lock()
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
	s := a.snapshotLocked()
	a.mu.Unlock()
	if a.store == nil {
		return nil
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	err = a.store.StoreDesync(a.partition, data)
	a.mu.Lock()
	if err != nil {
		a.persistenceError = err.Error()
	} else {
		a.persistenceError = ""
	}
	a.mu.Unlock()
	return err
}
func (a *Adaptive) Close() error { a.mu.Lock(); a.closed = true; a.mu.Unlock(); return a.Flush() }
func (a *Adaptive) Clear() error {
	a.persistMu.Lock()
	defer a.persistMu.Unlock()
	a.mu.Lock()
	a.entries = map[string]*Entry{}
	a.current = ""
	a.reason = "cleared"
	a.lastSwitch = ""
	a.persistenceError = ""
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
	a.mu.Unlock()
	if a.store != nil {
		return a.store.ClearDesync(a.partition)
	}
	return nil
}
func (a *Adaptive) pruneLocked(now time.Time) {
	for k, e := range a.entries {
		if now.Sub(e.Updated) > time.Duration(a.options.Adaptive.TTL) {
			delete(a.entries, k)
		}
	}
	for len(a.entries) > a.options.Adaptive.MaxEntries {
		var oldest string
		var date time.Time
		for k, e := range a.entries {
			if oldest == "" || e.Updated.Before(date) {
				oldest, date = k, e.Updated
			}
		}
		delete(a.entries, oldest)
	}
}
func (a *Adaptive) acquire(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	limit := a.options.Adaptive.MaxConcurrent
	if a.closed || a.total >= limit*16 || a.active[key] >= limit {
		return false
	}
	a.total++
	a.active[key]++
	return true
}
func (a *Adaptive) release(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active[key] > 0 {
		a.active[key]--
		a.total--
		if a.active[key] == 0 {
			delete(a.active, key)
		}
	}
}
func destinationKeys(d M.Socksaddr, generation uint64) []string {
	suffix := fmt.Sprintf("|route:%d", generation)
	keys := []string{"host:" + strings.ToLower(d.String()) + suffix}
	if d.IsDomain() {
		host := strings.TrimSuffix(strings.ToLower(d.Fqdn), ".")
		if parent, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil && parent != host {
			keys = append(keys, "parent:"+parent+fmt.Sprintf(":%d", d.Port)+suffix)
		}
	} else if d.Addr.IsValid() {
		bits := 24
		if d.Addr.Is6() {
			bits = 56
		}
		keys = append(keys, "subnet:"+netip.PrefixFrom(d.Addr, bits).Masked().String()+fmt.Sprintf(":%d", d.Port)+suffix)
	}
	return append(keys, "global"+suffix)
}
func (a *Adaptive) ranked(keys []string) []option.DesyncOptions {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneLocked(time.Now())
	weight := func(id string) float64 {
		for i, key := range keys {
			e := a.entries[key]
			if e == nil {
				continue
			}
			s, ok := e.Strategies[id]
			if !ok {
				continue
			}
			if i > 0 && !strings.HasPrefix(key, "global") && (len(e.Hosts) < 3 || s.Success < 8) {
				continue
			}
			n := s.Success + s.Failure
			return (float64(s.Success)+1)/(float64(n)+2) - float64(i)*0.03 - s.LatencyMS/1e7
		}
		return .5
	}
	type weightedStrategy struct {
		options option.DesyncOptions
		weight  float64
	}
	weighted := make([]weightedStrategy, len(a.catalog))
	for i, candidate := range a.catalog {
		weighted[i] = weightedStrategy{options: candidate, weight: weight(strategyID(candidate))}
	}
	sort.SliceStable(weighted, func(i, j int) bool { return weighted[i].weight > weighted[j].weight })
	candidates := make([]option.DesyncOptions, len(weighted))
	for i, candidate := range weighted {
		candidates[i] = cloneDesyncOptions(candidate.options)
	}
	return candidates
}
func (a *Adaptive) observe(keys []string, id, reason string, success bool, latency time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}
	now := time.Now()
	for _, key := range keys {
		e := a.entries[key]
		if e == nil {
			e = &Entry{Strategies: map[string]Score{}}
			a.entries[key] = e
		}
		s := e.Strategies[id]
		if success {
			s.Success++
		} else {
			s.Failure++
		}
		if latency > 0 {
			ms := float64(latency.Microseconds()) / 1000
			if s.LatencyMS == 0 {
				s.LatencyMS = ms
			} else {
				s.LatencyMS = .8*s.LatencyMS + .2*ms
			}
		}
		s.LastReason = reason
		e.Strategies[id] = s
		e.Updated = now
		if len(e.Hosts) < 8 {
			seen := false
			for _, host := range e.Hosts {
				if host == keys[0] {
					seen = true
				}
			}
			if !seen {
				e.Hosts = append(e.Hosts, keys[0])
			}
		}
	}
	if a.current != "" && a.current != id {
		a.lastSwitch = a.current + " -> " + id + ": " + reason
	}
	a.current = id
	a.reason = reason
	a.pruneLocked(now)
	a.scheduleFlushLocked()
}

func (a *Adaptive) interfaceUpdated() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}
	// Persist the epoch alongside the entries: ordinary restarts restore the
	// current route's learning instead of resurrecting a pre-update epoch.
	a.routeGeneration++
	a.scheduleFlushLocked()
}

func (a *Adaptive) scheduleFlushLocked() {
	if a.store != nil && a.timer == nil && !a.closed {
		a.timer = time.AfterFunc(5*time.Second, func() { _ = a.Flush() })
	}
}

type tcpDial func(context.Context, context.Context, M.Socksaddr, option.DesyncOptions) (net.Conn, error)

func (a *Adaptive) DialContext(ctx context.Context, d M.Socksaddr, generation uint64, dial tcpDial) (net.Conn, error) {
	return a.dialContext(ctx, d, d, generation, dial)
}

// identity is the logical route/sniff hostname; d remains the actual dial target
// for every retry, so learning cannot change DNS, destination or socket routing.
func (a *Adaptive) dialContext(ctx context.Context, d, identity M.Socksaddr, generation uint64, dial tcpDial) (net.Conn, error) {
	a.mu.Lock()
	closed := a.closed
	a.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	keys := destinationKeys(identity, generation)
	if identity.IsDomain() && d.IsIP() {
		// Retain the conservative numeric subnet aggregate after the exact host
		// and parent domain; it has the same multi-host evidence gate as before.
		numeric := destinationKeys(d, generation)
		keys = append(keys[:len(keys)-1], numeric[1:]...)
	}
	candidates := a.ranked(keys)
	probe := a.acquire(keys[0])
	attempts := 1
	if probe {
		attempts = a.options.Adaptive.MaxAttempts
	}
	deadline := time.Now().Add(time.Duration(a.options.Adaptive.Timeout))
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	var c net.Conn
	var err error
	index := 0
	for ; index < attempts && index < len(candidates); index++ {
		trial, cancel := context.WithDeadline(ctx, deadline)
		start := time.Now()
		c, err = dial(trial, ctx, d, candidates[index])
		cancel()
		if err == nil {
			break
		}
		a.observe(keys, strategyID(candidates[index]), "connect: "+err.Error(), false, time.Since(start))
		if ctx.Err() != nil {
			break
		}
	}
	if err != nil {
		if probe {
			a.release(keys[0])
		}
		return nil, err
	}
	connCtx, connCancel := context.WithCancel(ctx)
	conn := &adaptiveConn{conn: c, ctx: connCtx, cancel: connCancel, adaptive: a, keys: keys, destination: d, dial: dial, candidates: candidates, index: index, attempts: attempts, deadline: deadline, started: time.Now(), probe: probe}
	if err = conn.prepareFirstFlightLocked(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	stop := context.AfterFunc(connCtx, func() { _ = conn.Close() })
	conn.mu.Lock()
	conn.stop = stop
	if probe && !conn.closed {
		conn.probeTimer = time.AfterFunc(time.Until(deadline), func() {
			conn.mu.Lock()
			defer conn.mu.Unlock()
			conn.expireProbeLocked()
		})
	}
	conn.mu.Unlock()
	return conn, nil
}
