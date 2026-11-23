//go:build linux && !android

package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"syscall"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"golang.org/x/sys/unix"
)

var kernelSetupAccess sync.Mutex

type linuxKernelDevice struct {
	link     netlink.Link
	rules    []*netlink.Rule
	relay    *kernelUDPRelay
	dialer   net.Dialer
	listener net.ListenConfig
	closed   bool
}

func startKernelDevice(endpoint *Endpoint) (_ kernelDevice, err error) {
	options := endpoint.options
	kind := options.KernelKind
	switch kind {
	case C.TypeWireGuard, C.TypePhobos:
		if options.Amnezia != nil && *options.Amnezia != (AmneziaOptions{}) {
			return nil, fmt.Errorf("%w: WireGuard kernel module cannot apply Amnezia options", errKernelUnavailable)
		}
	case C.TypeAmneziaWG:
	default:
		return nil, errKernelUnavailable
	}
	linkKind := kind
	useRelay := options.KernelDetour
	if kind == C.TypePhobos {
		if options.Phobos == nil {
			return nil, fmt.Errorf("%w: Phobos relay requires obfuscation", errKernelUnavailable)
		}
		linkKind = C.TypeWireGuard
		useRelay = true
	}
	var mark uint32
	if !useRelay {
		mark, err = kernelRoutingMark(options)
		if err != nil {
			return nil, err
		}
	}
	for _, peer := range endpoint.peers {
		if peer.reserved != ([3]uint8{}) {
			return nil, fmt.Errorf("%w: a peer uses reserved bytes", errKernelUnavailable)
		}
	}
	if len(options.Address) == 0 {
		return nil, fmt.Errorf("%w: no interface addresses configured", errKernelUnavailable)
	}
	for _, prefix := range options.Address {
		address := prefix.Addr()
		if !prefix.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address.Is4In6() {
			return nil, fmt.Errorf("%w: unsupported interface address %s", errKernelUnavailable, prefix)
		}
	}

	var (
		link  netlink.Link
		relay *kernelUDPRelay
		peers []peerConfig
	)
	if useRelay {
		relay, peers, link, err = newKernelUDPRelay(endpoint, linkKind)
	} else {
		link, err = createKernelLink(options.Name, linkKind, options.MTU, netlink.LinkAdd)
	}
	if err != nil {
		return nil, err
	}
	device := &linuxKernelDevice{link: link, relay: relay}
	defer func() {
		if err != nil {
			if closeErr := device.Close(); closeErr != nil {
				err = fmt.Errorf("clean up %s after %w: %w", link.Attrs().Name, err, closeErr)
			}
		}
	}()
	family, err := netlink.GenlFamilyGet(linkKind)
	if err != nil {
		return nil, kernelSetupError("find "+linkKind+" generic netlink family", err)
	}
	config := kernelConfig{family: family, index: link.Attrs().Index, amnezia: kind == C.TypeAmneziaWG}
	listenPort := options.ListenPort
	if relay != nil {
		listenPort = 0
	} else {
		peers, err = resolveKernelPeers(endpoint)
		if err != nil {
			return nil, err
		}
	}
	err = config.apply(endpoint, mark, listenPort, peers)
	if err != nil {
		return nil, err
	}

	err = device.addAddresses(options.Address, options.System)
	if err != nil {
		return nil, err
	}
	err = device.SetUp(true)
	if err != nil {
		return nil, kernelSetupError("bring up kernel WireGuard interface", err)
	}
	err = device.addRoutes(options.Address, endpoint.deviceOptions.AllowedAddress)
	if err != nil {
		return nil, kernelSetupError("add kernel WireGuard routes", err)
	}
	if device.relay != nil {
		port, err := config.listenPort()
		if err != nil {
			return nil, kernelSetupError("read kernel WireGuard relay port", err)
		}
		device.relay.start(port)
	}
	var outputMark uint32
	if networkManager := service.FromContext[adapter.NetworkManager](options.Context); networkManager != nil {
		outputMark = networkManager.AutoRedirectOutputMark()
	}
	socketControl := func(network, address string, conn syscall.RawConn) error {
		return control.Raw(conn, func(fd uintptr) error {
			if outputMark != 0 {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(outputMark)); err != nil {
					return err
				}
			}
			return unix.BindToDevice(int(fd), link.Attrs().Name)
		})
	}
	device.dialer.Control = socketControl
	device.listener.Control = socketControl
	options.Logger.Info("started kernel ", kind, " at ", link.Attrs().Name)
	return device, nil
}

func kernelRoutingMark(options EndpointOptions) (uint32, error) {
	dial := options.DialerOptions
	if dial.Detour != "" || dial.BindInterface != "" || dial.Inet4BindAddress != nil || dial.Inet6BindAddress != nil ||
		dial.ProtectPath != "" || dial.NetNs != "" || dial.ReuseAddr || dial.UDPFragment != nil ||
		dial.NetworkStrategy != nil || len(dial.NetworkType) > 0 || len(dial.FallbackNetworkType) > 0 {
		return 0, fmt.Errorf("%w: outer UDP socket uses custom dialer options", errKernelUnavailable)
	}
	mark := uint32(dial.RoutingMark)
	networkManager := service.FromContext[adapter.NetworkManager](options.Context)
	if networkManager == nil {
		return mark, nil
	}
	defaults := networkManager.DefaultOptions()
	if defaults.BindInterface != "" || networkManager.ProtectFunc() != nil {
		return 0, fmt.Errorf("%w: outer UDP socket requires interface binding or protection", errKernelUnavailable)
	}
	if mark == 0 {
		mark = defaults.RoutingMark
	}
	if redirectMark := networkManager.AutoRedirectOutputMark(); redirectMark != 0 {
		if mark != 0 {
			return 0, fmt.Errorf("%w: routing mark conflicts with auto-redirect", errKernelUnavailable)
		}
		mark = redirectMark
	} else if networkManager.AutoDetectInterface() {
		return 0, fmt.Errorf("%w: outer UDP socket requires auto_detect_interface", errKernelUnavailable)
	}
	return mark, nil
}

func createKernelLink(name, kind string, mtu uint32, add func(netlink.Link) error) (netlink.Link, error) {
	kernelSetupAccess.Lock()
	defer kernelSetupAccess.Unlock()
	if name == "" {
		prefix := "wg"
		if kind == C.TypeAmneziaWG {
			prefix = "awg"
		}
		name = tun.CalculateInterfaceName(prefix)
	}
	attrs := netlink.NewLinkAttrs()
	attrs.Name = name
	attrs.MTU = int(mtu)
	link := &netlink.GenericLink{LinkAttrs: attrs, LinkType: kind}
	err := add(link)
	if err != nil {
		return nil, kernelSetupError("create "+kind+" interface", err)
	}
	if link.Index == 0 {
		movedLink, err := netlink.LinkByName(name)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("find newly created interface %q: %w", name, err), netlink.LinkDel(link))
		}
		return movedLink, nil
	}
	return link, nil
}

func (d *linuxKernelDevice) addAddresses(addresses []netip.Prefix, system bool) error {
	kernelSetupAccess.Lock()
	defer kernelSetupAccess.Unlock()

	if slices.ContainsFunc(addresses, func(address netip.Prefix) bool { return address.Addr().Is4() }) {
		conflict, err := conflictingLocalIPv4(addresses)
		if err != nil {
			return kernelSetupError("list local IPv4 addresses", err)
		}
		if conflict.IsValid() {
			if system {
				return fmt.Errorf("system mode requires a unique local IPv4 address: %s is already assigned", conflict)
			}
			return fmt.Errorf("%w: local IPv4 address %s is already assigned", errKernelUnavailable, conflict)
		}
	}
	for _, address := range addresses {
		flags := unix.IFA_F_NOPREFIXROUTE
		if address.Addr().Is6() {
			flags |= unix.IFA_F_NODAD
		}
		err := netlink.AddrAdd(d.link, &netlink.Addr{IPNet: prefixIPNet(address), Flags: flags})
		if err != nil {
			return kernelSetupError("add kernel WireGuard interface address", err)
		}
	}
	return nil
}

// The source rule cannot distinguish tunnels with the same IPv4 address.
func conflictingLocalIPv4(addresses []netip.Prefix) (netip.Addr, error) {
	assigned, err := netlink.AddrList(nil, unix.AF_INET)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, address := range addresses {
		ip := address.Addr()
		if ip.Is4() && slices.ContainsFunc(assigned, func(existing netlink.Addr) bool { return existing.IP.Equal(ip.AsSlice()) }) {
			return ip, nil
		}
	}
	return netip.Addr{}, nil
}

func (d *linuxKernelDevice) addRoutes(addresses, allowed []netip.Prefix) error {
	if len(allowed) == 0 {
		return nil
	}
	kernelSetupAccess.Lock()
	defer kernelSetupAccess.Unlock()
	table, err := freeTunnelRouteTable(d.link.Attrs().Index)
	if err != nil {
		return err
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		ipv4 := family == unix.AF_INET
		if !slices.ContainsFunc(addresses, func(address netip.Prefix) bool { return address.Addr().Is4() == ipv4 }) {
			continue
		}
		hasRoute := false
		for _, prefix := range allowed {
			if prefix.Addr().Is4() != ipv4 {
				continue
			}
			err = netlink.RouteAdd(&netlink.Route{
				LinkIndex: d.link.Attrs().Index,
				Family:    family,
				Dst:       prefixIPNet(prefix),
				Table:     table,
				Scope:     netlink.SCOPE_LINK,
			})
			if err != nil {
				return err
			}
			hasRoute = true
		}
		if hasRoute {
			err = addTunnelRouteRules(&d.rules, d.link.Attrs().Name, family, table, addresses)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func addTunnelRouteRules(rules *[]*netlink.Rule, name string, family, table int, addresses []netip.Prefix) error {
	// Match sockets bound to this tunnel.
	rule := netlink.NewRule()
	rule.Family = family
	rule.Priority = 100
	rule.Table = table
	rule.OifName = name
	if err := netlink.RuleAdd(rule); err != nil {
		return err
	}
	*rules = append(*rules, rule)
	// Reverse-path validation can look up the remote IP without an output interface.
	for _, address := range addresses {
		ip := address.Addr()
		if ip.Is4() != (family == unix.AF_INET) {
			continue
		}
		sourceRule := netlink.NewRule()
		sourceRule.Family = family
		sourceRule.Priority = 101
		sourceRule.Table = table
		sourceRule.Src = netip.PrefixFrom(ip, ip.BitLen())
		if err := netlink.RuleAdd(sourceRule); err != nil {
			return err
		}
		*rules = append(*rules, sourceRule)
	}
	return nil
}

func removeTunnelRouteRules(rules []*netlink.Rule) error {
	var errs []error
	for _, rule := range rules {
		if err := netlink.RuleDel(rule); err != nil && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, fmt.Errorf("remove WireGuard routing rule: %w", err))
		}
	}
	return errors.Join(errs...)
}

func freeTunnelRouteTable(index int) (int, error) {
	const first, size = 0x53420000, 1 << 16
	used := make(map[int]bool)
	routes, err := netlink.RouteListFiltered(unix.AF_UNSPEC, &netlink.Route{}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return 0, err
	}
	for _, route := range routes {
		used[route.Table] = true
	}
	rules, err := netlink.RuleList(unix.AF_UNSPEC)
	if err != nil {
		return 0, err
	}
	for _, rule := range rules {
		used[rule.Table] = true
	}
	for offset := range size {
		table := first + (index+offset)%size
		if !used[table] {
			return table, nil
		}
	}
	return 0, errors.New("no free WireGuard routing table")
}

func prefixIPNet(prefix netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: prefix.Addr().AsSlice(), Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())}
}

func (d *linuxKernelDevice) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.dialer.DialContext(ctx, N.NetworkName(network), destination.String())
}

func (d *linuxKernelDevice) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	network := "udp6"
	if destination.IsIPv4() {
		network = "udp4"
	}
	return d.listener.ListenPacket(ctx, network, ":0")
}

func (d *linuxKernelDevice) SetUp(up bool) error {
	if d.closed {
		return nil
	}
	if up {
		return netlink.LinkSetUp(d.link)
	}
	return netlink.LinkSetDown(d.link)
}

func (d *linuxKernelDevice) BindUpdate() error {
	if d.closed || d.relay == nil {
		return nil
	}
	return d.relay.rebind()
}

func (d *linuxKernelDevice) Close() error {
	if d.closed {
		return nil
	}
	d.closed = true
	var errs []error
	if d.relay != nil {
		errs = append(errs, d.relay.Close())
	}
	errs = append(errs, removeTunnelRouteRules(d.rules))
	if err := netlink.LinkDel(d.link); err != nil && !errors.Is(err, unix.ENODEV) {
		errs = append(errs, fmt.Errorf("remove kernel WireGuard interface: %w", err))
	}
	return errors.Join(errs...)
}

func kernelSetupError(action string, err error) error {
	switch {
	case errors.Is(err, errKernelUnavailable):
		return fmt.Errorf("%s: %w", action, err)
	case errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.EPROTONOSUPPORT), errors.Is(err, unix.EAFNOSUPPORT),
		errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENODEV), errors.Is(err, unix.ENOSYS),
		errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		return fmt.Errorf("%w: %s: %w", errKernelUnavailable, action, err)
	default:
		return fmt.Errorf("%s: %w", action, err)
	}
}
