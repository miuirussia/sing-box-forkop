//go:build linux && !android

package wireguard

import (
	"errors"
	"fmt"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-tun"

	"golang.org/x/sys/unix"
)

func startSystemTun(options tun.Options) (tun.Tun, func() error, error) {
	if len(options.Inet4Address) == 0 || len(options.Inet4RouteAddress) == 0 {
		device, err := openSystemTun(options)
		return device, nil, err
	}

	kernelSetupAccess.Lock()
	defer kernelSetupAccess.Unlock()
	conflict, err := conflictingLocalIPv4(options.Inet4Address)
	if err != nil {
		return nil, nil, fmt.Errorf("list local IPv4 addresses: %w", err)
	}
	if conflict.IsValid() {
		return nil, nil, fmt.Errorf("system mode requires a unique local IPv4 address: %s is already assigned", conflict)
	}
	options.IPRoute2TableIndex, err = freeTunnelRouteTable(0)
	if err != nil {
		return nil, nil, err
	}
	device, err := openSystemTun(options)
	if err != nil {
		return nil, nil, err
	}

	// sing-tun installs the routes in this table, with an interface rule only for IPv6.
	var rules []*netlink.Rule
	err = addTunnelRouteRules(&rules, options.Name, unix.AF_INET, options.IPRoute2TableIndex, options.Inet4Address)
	if err != nil {
		return nil, nil, errors.Join(fmt.Errorf("add WireGuard TUN routing rules: %w", err), removeTunnelRouteRules(rules), device.Close())
	}
	return device, func() error { return removeTunnelRouteRules(rules) }, nil
}
