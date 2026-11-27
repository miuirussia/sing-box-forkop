package desync

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	engine "github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const Capability = "forkop-desync-v1"

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.DesyncOptions](registry, C.TypeDesync, NewOutbound)
}

type Outbound struct {
	networkManager adapter.NetworkManager
	outbound.Adapter
	ctx      context.Context
	options  option.DesyncOptions
	dialer   N.Dialer
	adaptive *Adaptive
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DesyncOptions) (adapter.Outbound, error) {
	options, err := option.NormalizeDesyncOptions(options)
	if err != nil {
		return nil, err
	}
	if err = engine.Validate(options); err != nil {
		return nil, err
	}
	socketControl, err := engine.SocketControl(options)
	if err != nil {
		return nil, err
	}
	options.SocketControl = socketControl
	options.SocketControlOwnsBind = options.SynData != ""
	options.UDPFragmentDefault = true
	d, err := dialer.NewWithOptions(dialer.Options{Context: ctx, Options: options.DialerOptions, RemoteIsDomain: true, DirectOutbound: true})
	if err != nil {
		return nil, err
	}
	h := &Outbound{networkManager: service.FromContext[adapter.NetworkManager](ctx), Adapter: outbound.NewAdapterWithDialerOptions(C.TypeDesync, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions), ctx: ctx, options: options, dialer: d}
	if options.AutoTune != nil && *options.AutoTune {
		h.adaptive = NewAdaptive(tag, options)
	}
	return h, nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if h.adaptive != nil && stage == adapter.StartStateStart {
		if store, ok := service.FromContext[adapter.CacheFile](h.ctx).(Store); ok {
			h.adaptive.store = store
		}
		if err := h.adaptive.Load(); err != nil {
			return err
		}
		scope.Add(h.adaptive.Close)
	}
	return nil
}
func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	if h.adaptive != nil {
		h.adaptive.interfaceUpdated()
	}
}
func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	network = N.NetworkName(network)
	if network != N.NetworkTCP && network != N.NetworkUDP {
		return nil, fmt.Errorf("desync: unsupported network %q", network)
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	identity := destination
	if destination.IsIP() && metadata.Destination.Port == destination.Port {
		if metadata.Destination.IsDomain() && slices.Contains(metadata.DestinationAddresses, destination.Addr) {
			identity = metadata.Destination
		} else if metadata.Destination.Addr == destination.Addr && M.IsDomainName(metadata.Domain) {
			identity = M.Socksaddr{Fqdn: metadata.Domain, Port: destination.Port}
		}
	}
	if identity.IsDomain() {
		identity.Fqdn = strings.TrimSuffix(strings.ToLower(identity.Fqdn), ".")
	}
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	if network == N.NetworkUDP {
		c, err := h.dialer.DialContext(ctx, network, destination)
		if err != nil {
			return nil, err
		}
		wrapped, err := engine.NewUDPConn(ctx, c, h.options)
		if err != nil {
			c.Close()
		}
		return wrapped, err
	}
	if h.adaptive != nil {
		return h.adaptive.dialContext(ctx, destination, identity, h.networkPartition(), h.dialTCP)
	}
	return h.dialTCP(ctx, ctx, destination, h.options)
}
func (h *Outbound) dialTCP(ctx context.Context, lifetime context.Context, destination M.Socksaddr, opts option.DesyncOptions) (net.Conn, error) {
	c, err := h.dialer.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		return nil, err
	}
	wrapped, err := engine.NewConn(lifetime, c, opts)
	if err != nil {
		c.Close()
	}
	return wrapped, err
}
func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	if destination.IsDomain() {
		resolver, ok := h.dialer.(dialer.ResolveDialer)
		if !ok {
			return nil, fmt.Errorf("desync: domain UDP requires the configured resolver")
		}
		router := service.FromContext[adapter.DNSRouter](h.ctx)
		addresses, err := router.Lookup(ctx, destination.Fqdn, resolver.QueryOptions())
		if err != nil {
			return nil, err
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("desync: no addresses for %s", destination.Fqdn)
		}
		// Keep the resolver's logical NAT outside the engine: raw fake injection
		// and ordinary sends must see exactly the same numeric destination.
		conn, address, err := N.ListenSerial(ctx, h.dialer, destination, addresses)
		if err != nil {
			return nil, err
		}
		wrapped, err := engine.NewPacketConn(ctx, conn, h.options)
		if err != nil {
			conn.Close()
			return nil, err
		}
		actual := M.SocksaddrFrom(address, destination.Port)
		return newDomainPacketConn(wrapped, actual, destination), nil
	}
	conn, err := h.dialer.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	wrapped, err := engine.NewPacketConn(ctx, conn, h.options)
	if err != nil {
		conn.Close()
	}
	return wrapped, err
}
func (h *Outbound) DesyncStats() Snapshot {
	if h.adaptive == nil {
		return Snapshot{Version: 1, Current: h.options.Mode, Reason: "manual strategy"}
	}
	return h.adaptive.Stats()
}
func (h *Outbound) ClearDesync() error {
	if h.adaptive == nil {
		return nil
	}
	return h.adaptive.Clear()
}

// The existing network environment hash includes gateway identity and Wi-Fi SSID.
// Interface prefixes provide a stable fallback on platforms without a monitor.
func (h *Outbound) networkPartition() uint64 {
	fingerprint := h.networkFingerprint()
	if h.adaptive == nil {
		return fingerprint
	}
	h.adaptive.mu.Lock()
	generation := h.adaptive.routeGeneration
	h.adaptive.mu.Unlock()
	if generation == 0 {
		return fingerprint
	}
	var key [16]byte
	binary.BigEndian.PutUint64(key[:8], fingerprint)
	binary.BigEndian.PutUint64(key[8:], generation)
	sum := sha256.Sum256(key[:])
	return binary.BigEndian.Uint64(sum[:8])
}

func (h *Outbound) networkFingerprint() uint64 {
	if h.networkManager == nil {
		return 0
	}
	if env := h.networkManager.NetworkEnvironment(); env != 0 {
		return env
	}
	var networks []string
	for _, iface := range h.networkManager.NetworkInterfaces() {
		networks = append(networks, iface.Name)
		for _, addr := range iface.Addresses {
			networks = append(networks, addr.Masked().String())
		}
		for _, gateway := range iface.Gateways {
			networks = append(networks, gateway.String())
		}
	}
	sort.Strings(networks)
	data, _ := json.Marshal(networks)
	sum := sha256.Sum256(data)
	return binary.BigEndian.Uint64(sum[:8])
}
