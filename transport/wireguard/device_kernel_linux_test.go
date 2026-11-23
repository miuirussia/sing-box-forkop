//go:build linux && !android && with_gvisor

package wireguard

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/phobos"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/vishvananda/netns"

	"golang.org/x/sys/unix"
)

type kernelTestNetworkManager struct {
	adapter.NetworkManager
	redirectMark uint32
}

func (kernelTestNetworkManager) DefaultOptions() adapter.NetworkOptions {
	return adapter.NetworkOptions{}
}
func (kernelTestNetworkManager) ProtectFunc() control.Func        { return nil }
func (kernelTestNetworkManager) AutoDetectInterface() bool        { return true }
func (m kernelTestNetworkManager) AutoRedirectOutputMark() uint32 { return m.redirectMark }

func TestKernelWireGuardAutoDetectInterface(t *testing.T) {
	for _, mark := range []uint32{0, 123} {
		ctx := service.ContextWith[adapter.NetworkManager](context.Background(), kernelTestNetworkManager{redirectMark: mark})
		got, err := kernelRoutingMark(EndpointOptions{Context: ctx})
		if mark == 0 {
			if !errors.Is(err, errKernelUnavailable) {
				t.Fatalf("expected userspace fallback for auto_detect_interface, got %v", err)
			}
		} else if err != nil || got != mark {
			t.Fatalf("expected auto-redirect mark %d, got %d, %v", mark, got, err)
		}
	}
}

func TestKernelWireGuardFallback(t *testing.T) {
	key, _ := testKeyPair(t)
	endpoint := startTestEndpoint(t, EndpointOptions{
		Context:    context.Background(),
		Logger:     logger.NOP(),
		KernelKind: C.TypeWireGuard,
		DialerOptions: option.DialerOptions{
			Detour: "proxy",
		},
		Dialer:     listenDialer{},
		Address:    []netip.Prefix{netip.MustParsePrefix("10.77.0.2/32")},
		PrivateKey: key,
	}, false)
	if endpoint.UsesKernel() || endpoint.device == nil {
		t.Fatal("expected userspace device for a WireGuard UDP detour")
	}
}

func TestKernelWireGuardTunnel(t *testing.T) {
	if os.Getenv("SING_BOX_TEST_KERNEL_WIREGUARD") == "" {
		t.Skip("set SING_BOX_TEST_KERNEL_WIREGUARD inside a Linux network namespace with CAP_NET_ADMIN and CAP_SYS_ADMIN")
	}
	obfuscation, err := phobos.Normalize(&option.PhobosObfuscationOptions{Key: "test", Masking: "STUN"})
	if err != nil {
		t.Fatal(err)
	}
	amnezia := &AmneziaOptions{
		JC: 2, JMin: 40, JMax: 64, S1: 24, S2: 16, S3: 8, S4: 4,
		H1: &option.Range[uint32]{From: 101, To: 110},
		H2: &option.Range[uint32]{From: 201, To: 210},
		H3: &option.Range[uint32]{From: 301, To: 310},
		H4: &option.Range[uint32]{From: 401, To: 410},
		I1: "<b 0xdeadbeef>",
	}
	amnezia31 := *amnezia
	amnezia31.S3, amnezia31.S4 = 16, 16
	amnezia31.HeaderProtectionKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32))
	amnezia31.ContentPaddingAddition = &option.Range[uint32]{From: 1, To: 8}
	amnezia31.RandomTrailers = true
	amnezia31.DisableCookies = true
	for _, test := range []struct {
		name             string
		kind             string
		phobos           *phobos.Options
		amnezia          *AmneziaOptions
		detourHost       string
		blackholeFirst   bool
		system           bool
		multiDNS         bool
		duplicateAddress bool
	}{
		{name: "wireguard", kind: C.TypeWireGuard},
		{name: "wireguard duplicate IPv4 address", kind: C.TypeWireGuard, duplicateAddress: true},
		{name: "amneziawg", kind: C.TypeAmneziaWG, amnezia: amnezia},
		{name: "amneziawg 3.1", kind: C.TypeAmneziaWG, amnezia: &amnezia31},
		{name: "amneziawg system fallback recovers a silent detour", kind: C.TypeAmneziaWG, amnezia: amnezia, detourHost: "192.0.2.1", blackholeFirst: true, system: true},
		{name: "phobos", kind: C.TypePhobos, phobos: obfuscation},
		{name: "phobos detour", kind: C.TypePhobos, phobos: obfuscation, detourHost: "peer.test"},
		{name: "phobos detour IP", kind: C.TypePhobos, phobos: obfuscation, detourHost: "192.0.2.1"},
		{name: "phobos reconnects a silent detour", kind: C.TypePhobos, phobos: obfuscation, detourHost: "192.0.2.1", blackholeFirst: true},
		{name: "wireguard system", system: true},
		{name: "wireguard system fallback with detour", kind: C.TypeWireGuard, detourHost: "192.0.2.1", system: true},
		{name: "phobos system with detour", phobos: obfuscation, detourHost: "192.0.2.1", system: true},
		{name: "wireguard multi-address DNS", kind: C.TypeWireGuard, multiDNS: true},
		{name: "phobos multi-address DNS", kind: C.TypePhobos, phobos: obfuscation, multiDNS: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.amnezia == &amnezia31 {
				family, err := netlink.GenlFamilyGet(C.TypeAmneziaWG)
				if err != nil || family.MaxAttr < kernelNoCookies {
					t.Skip("AmneziaWG 3.1 module unavailable")
				}
			}
			loopback, err := netlink.LinkByName("lo")
			if err != nil {
				t.Fatal(err)
			}
			if err = netlink.LinkSetUp(loopback); err != nil {
				t.Fatal(err)
			}
			ctx := pause.WithDefaultManager(context.Background())
			clientPrivate, clientPublic := testKeyPair(t)
			serverPrivate, serverPublic := testKeyPair(t)
			listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			serverPort := uint16(listener.LocalAddr().(*net.UDPAddr).Port)
			if err = listener.Close(); err != nil {
				t.Fatal(err)
			}
			serverAddresses := []netip.Prefix{netip.MustParsePrefix("10.77.0.1/32"), netip.MustParsePrefix("fd77::1/128")}
			clientAddresses := []netip.Prefix{netip.MustParsePrefix("10.77.0.2/24"), netip.MustParsePrefix("fd77::2/64")}
			server := startTestEndpoint(t, EndpointOptions{
				Context: ctx, Logger: logger.NOP(), Dialer: listenDialer{}, Address: serverAddresses,
				PrivateKey: serverPrivate, ListenPort: serverPort, Phobos: test.phobos, Amnezia: test.amnezia,
				Peers: []PeerOptions{{PublicKey: clientPublic, AllowedIPs: clientAddresses}},
			}, false)
			clientOptions := EndpointOptions{
				Context: ctx, Logger: logger.NOP(), Dialer: listenDialer{}, Address: clientAddresses,
				PrivateKey: clientPrivate, KernelKind: test.kind, Name: "wg-test", Phobos: test.phobos, Amnezia: test.amnezia,
				ResolvePeer: func(string) ([]netip.Addr, error) {
					local := netip.MustParseAddr("127.0.0.1")
					if test.multiDNS {
						return []netip.Addr{netip.MustParseAddr("2001:db8::2"), local}, nil
					}
					return []netip.Addr{local, local}, nil
				},
				Peers: []PeerOptions{{
					PublicKey: serverPublic, Endpoint: M.ParseSocksaddrHostPort("peer.test", serverPort),
					AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
				}},
			}
			if test.detourHost != "" {
				clientOptions.Dialer = &sessionProxy{blackholeFirst: test.blackholeFirst}
				clientOptions.DialerOptions.Detour = "proxy"
				clientOptions.ResolvePeer = nil
				clientOptions.Peers[0].Endpoint = M.ParseSocksaddrHostPort(test.detourHost, serverPort)
			}
			if test.system {
				finder := control.NewDefaultInterfaceFinder()
				clientOptions.Context = service.ContextWith[adapter.NetworkManager](ctx, systemTestNetworkManager{finder: finder})
				clientOptions.System = true
				clientOptions.Address = []netip.Prefix{netip.MustParsePrefix("10.77.0.2/32")}
				clientOptions.CreateDialer = func(name string) N.Dialer {
					options := option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{
						BindInterface: name, UDPFragmentDefault: true, ConnectTimeout: badoption.Duration(8 * time.Second),
					}}
					d, err := dialer.NewDefault(clientOptions.Context, options)
					if err != nil {
						t.Fatal(err)
					}
					return d
				}
			}
			if test.duplicateAddress {
				firstOptions := clientOptions
				firstOptions.Name = "wg-first"
				firstOptions.PrivateKey, _ = testKeyPair(t)
				firstOptions.Address = []netip.Prefix{clientAddresses[0]}
				first := startTestEndpoint(t, firstOptions, true)
				if !first.UsesKernel() {
					t.Fatal("expected the first endpoint to use the kernel")
				}
				systemOptions := clientOptions
				systemOptions.System = true
				system, err := NewEndpoint(systemOptions)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = system.Close() })
				if err = system.Start(true); err == nil || errors.Is(err, errKernelUnavailable) {
					t.Fatalf("expected an error for an IPv4 address conflict in system mode, got %v", err)
				}
			}
			client := startTestEndpoint(t, clientOptions, clientOptions.Peers[0].Endpoint.IsDomain())
			if test.system {
				if _, ok := client.tunDevice.(*systemStackDevice); !ok || client.UsesKernel() {
					t.Fatal("expected a userspace system device")
				}
				testKernelEcho(t, client, server.tunDevice.(*stackDevice), serverAddresses[0].Addr())
				testSystemRulesRemoved(t, client, clientOptions.Name)
				return
			}
			if test.duplicateAddress {
				if client.UsesKernel() {
					t.Fatal("expected userspace fallback for a duplicate IPv4 address")
				}
				testKernelEcho(t, client, server.tunDevice.(*stackDevice), serverAddresses[0].Addr())
				return
			}
			if test.multiDNS {
				if client.UsesKernel() {
					t.Fatal("expected userspace fallback with multiple distinct peer addresses")
				}
				testKernelEcho(t, client, server.tunDevice.(*stackDevice), serverAddresses[0].Addr())
				return
			}
			if !client.UsesKernel() {
				if test.kind == C.TypeAmneziaWG {
					_, err = netlink.GenlFamilyGet(C.TypeAmneziaWG)
					if errors.Is(err, unix.ENOENT) {
						t.Skip("AmneziaWG module unavailable")
					}
				}
				t.Fatal("kernel backend fell back to userspace")
			}
			for i, address := range serverAddresses {
				if i > 0 && test.phobos != nil {
					if err = client.BindUpdate(); err != nil {
						t.Fatal(err)
					}
				}
				testKernelEcho(t, client, server.tunDevice.(*stackDevice), address.Addr())
			}
			routes, err := netlink.RouteList(nil, unix.AF_UNSPEC)
			if err != nil {
				t.Fatal(err)
			}
			device := client.kernelDevice.(*linuxKernelDevice)
			if test.phobos != nil {
				testKernelPhobosSocketNamespace(t, device.relay)
			}
			if slices.ContainsFunc(routes, func(route netlink.Route) bool { return route.LinkIndex == device.link.Attrs().Index }) {
				t.Fatal("kernel WireGuard interface added routes to the main table")
			}
			table := device.rules[0].Table
			if err = client.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err = netlink.LinkByName("wg-test"); err == nil {
				t.Fatal("kernel WireGuard interface still exists after close")
			}
			rules, err := netlink.RuleList(unix.AF_UNSPEC)
			if err != nil {
				t.Fatal(err)
			}
			if slices.ContainsFunc(rules, func(rule netlink.Rule) bool { return rule.Table == table }) {
				t.Fatal("kernel WireGuard policy rule still exists after close")
			}
		})
	}
}

func testKernelPhobosSocketNamespace(t *testing.T, relay *kernelPhobosRelay) {
	t.Helper()
	outerNamespace, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer outerNamespace.Close()
	processNamespace, err := netns.GetFromPath("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer processNamespace.Close()
	if !processNamespace.Equal(outerNamespace) {
		t.Fatal("Phobos setup moved the process main thread to a different network namespace")
	}
	for _, peer := range relay.peers {
		rawConn, err := peer.local.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var namespaceFD int
		err = control.Raw(rawConn, func(fd uintptr) error {
			var ioctlErr error
			namespaceFD, ioctlErr = unix.IoctlRetInt(int(fd), unix.SIOCGSKNS)
			return ioctlErr
		})
		if err != nil {
			t.Fatal(err)
		}
		innerNamespace := netns.NsHandle(namespaceFD)
		sharedNamespace := innerNamespace.Equal(outerNamespace)
		if err = innerNamespace.Close(); err != nil {
			t.Fatal(err)
		}
		if sharedNamespace {
			t.Fatal("Phobos loopback socket is in the outer network namespace")
		}
	}
}

func testKernelEcho(t *testing.T, client *Endpoint, server *stackDevice, address netip.Addr) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	const port = 12345
	fullAddress := tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tun.AddressFromAddr(address), Port: port}
	protocol := ipv6.ProtocolNumber
	if address.Is4() {
		protocol = ipv4.ProtocolNumber
	}
	listener, err := gonet.ListenTCP(server.stack, fullAddress, protocol)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			conn.Write([]byte("tcp"))
		}
	}()
	destination := M.SocksaddrFrom(address, port)
	conn, err := client.DialContext(ctx, "tcp", destination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err = conn.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(conn)
	if err != nil || string(reply) != "tcp" {
		t.Fatalf("read TCP reply %q from %s: %v", reply, address, err)
	}

	udpServer, err := gonet.DialUDP(server.stack, &fullAddress, nil, protocol)
	if err != nil {
		t.Fatal(err)
	}
	defer udpServer.Close()
	go func() {
		var data [3]byte
		n, remote, err := udpServer.ReadFrom(data[:])
		if err == nil {
			udpServer.WriteTo(data[:n], remote)
		}
	}()
	udpClient, err := client.ListenPacket(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer udpClient.Close()
	if err = udpClient.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if _, err = udpClient.WriteTo([]byte("udp"), net.UDPAddrFromAddrPort(destination.AddrPort())); err != nil {
		t.Fatal(err)
	}
	var data [16]byte
	n, _, err := udpClient.ReadFrom(data[:])
	if err != nil || string(data[:n]) != "udp" {
		t.Fatalf("read UDP reply %q from %s: %v", data[:n], address, err)
	}
}
