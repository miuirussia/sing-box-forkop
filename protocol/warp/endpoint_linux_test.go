//go:build linux && !android && with_wireguard && with_gvisor

package warp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/cloudflare"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/warp"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestWARPLinuxBackends(t *testing.T) {
	if os.Getenv("SING_BOX_TEST_KERNEL_WIREGUARD") == "" {
		t.Skip("set SING_BOX_TEST_KERNEL_WIREGUARD inside a Linux network namespace with CAP_NET_ADMIN and CAP_SYS_ADMIN")
	}
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err = netlink.LinkSetUp(loopback); err != nil {
		t.Fatal(err)
	}
	// Keep sing-box's network monitor active without giving the namespace Internet access.
	uplink := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "warp-test-link"}}
	if err = netlink.LinkAdd(uplink); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(uplink) })
	if err = netlink.LinkSetUp(uplink); err != nil {
		t.Fatal(err)
	}
	address, err := netlink.ParseAddr("192.0.2.1/24")
	if err != nil {
		t.Fatal(err)
	}
	if err = netlink.AddrAdd(uplink, address); err != nil {
		t.Fatal(err)
	}
	if err = netlink.RouteAdd(&netlink.Route{LinkIndex: uplink.Index, Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}}); err != nil {
		t.Fatal(err)
	}
	obfuscation := &option.OneSidedAmnezia{JC: 2, JMin: 40, JMax: 64}
	fallbackObfuscation := &option.OneSidedAmnezia{JC: 2, I1: "<b 0xdeadbeef>"}
	for _, test := range []struct {
		name           string
		kind           string
		detourHost     string
		amnezia        *option.OneSidedAmnezia
		system         bool
		blackholeFirst bool
		resolvePeer    bool
	}{
		{name: "plain kernel", kind: C.TypeWireGuard},
		{name: "obfuscated kernel", kind: C.TypeAmneziaWG, amnezia: obfuscation},
		{name: "plain kernel through detour by name", kind: C.TypeWireGuard, detourHost: "warp-peer.test"},
		{name: "plain kernel through detour with domain resolver", kind: C.TypeWireGuard, detourHost: "192.0.2.2", resolvePeer: true},
		{name: "obfuscated kernel through detour by IP", kind: C.TypeAmneziaWG, detourHost: "192.0.2.2", amnezia: obfuscation},
		{
			name: "obfuscated kernel reconnects a silent detour", kind: C.TypeAmneziaWG,
			detourHost: "192.0.2.2", amnezia: obfuscation, blackholeFirst: true,
		},
		{
			name: "obfuscated system fallback through detour", kind: "tuntap",
			detourHost: "192.0.2.2", amnezia: fallbackObfuscation, system: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.kind == C.TypeAmneziaWG {
				if _, err := netlink.GenlFamilyGet(C.TypeAmneziaWG); err != nil {
					t.Skip("AmneziaWG kernel module unavailable")
				}
			}
			ctx := include.Context(context.Background())
			clientKey, serverKey := warpTestKey(t), warpTestKey(t)
			udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			port := udp.LocalAddr().(*net.UDPAddr).Port
			udp.Close()
			cacheOptions := option.CacheFileOptions{Enabled: true, Path: filepath.Join(t.TempDir(), "warp.db"), StoreWARPConfig: true}
			seedWARPTestProfile(t, ctx, cacheOptions, clientKey, serverKey.PublicKey(), port)
			warpOptions := &option.WARPEndpointOptions{Kernel: true, Name: "warp-test", Amnezia: test.amnezia, System: test.system}
			firstPacket := make(chan []byte, 1)
			outbounds := []option.Outbound{{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{}}}
			if test.detourHost != "" {
				const detourType = "warp-test-detour"
				registry := service.FromContext[adapter.OutboundRegistry](ctx).(*outbound.Registry)
				outbound.Register[struct{}](registry, detourType, func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ struct{}) (adapter.Outbound, error) {
					return &warpTestDetour{
						Adapter:        outbound.NewAdapter(detourType, tag, []string{N.NetworkUDP}, nil),
						peer:           M.ParseSocksaddrHostPort(test.detourHost, uint16(port)),
						blackholeFirst: test.blackholeFirst,
						firstPacket:    firstPacket,
					}, nil
				})
				outbounds = append(outbounds, option.Outbound{Type: detourType, Tag: "proxy"})
				warpOptions.Address = test.detourHost
				warpOptions.Detour = "proxy"
			}
			var dnsOptions *option.DNSOptions
			if test.resolvePeer {
				hostsPath := filepath.Join(t.TempDir(), "hosts")
				if err := os.WriteFile(hostsPath, []byte(test.detourHost+" warp-peer.test\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				dnsOptions = &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{
					Servers: []option.DNSServerOptions{{
						Type: C.DNSTypeHosts, Tag: "warp-hosts", Options: &option.HostsDNSServerOptions{Path: []string{hostsPath}},
					}},
				}}
				warpOptions.Address = "warp-peer.test"
				warpOptions.DomainResolver = &option.DomainResolveOptions{Server: "warp-hosts"}
			}
			instance, err := box.New(box.Options{Context: ctx, Options: option.Options{
				Log:          &option.LogOptions{Level: "warn"},
				DNS:          dnsOptions,
				Experimental: &option.ExperimentalOptions{CacheFile: &cacheOptions},
				Endpoints: []option.Endpoint{
					{Type: C.TypeWireGuard, Tag: "server", Options: &option.WireGuardEndpointOptions{WireGuardCommonOptions: option.WireGuardCommonOptions{
						PrivateKey: serverKey.String(), ListenPort: uint16(port), Address: []netip.Prefix{netip.MustParsePrefix("10.77.0.1/32")},
						Peers: []option.WireGuardPeer{{PublicKey: clientKey.PublicKey().String(), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.77.0.2/32")}}},
					}}},
					{Type: C.TypeWARP, Tag: "warp", Options: warpOptions},
				},
				Outbounds: outbounds,
				Route:     &option.RouteOptions{Final: "direct"},
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer instance.Close()
			if err = instance.Start(); err != nil {
				t.Fatal(err)
			}
			endpoint, ok := instance.Endpoint().Get("warp")
			if !ok {
				t.Fatal("WARP endpoint unavailable")
			}
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				conn, err := listener.Accept()
				if err == nil {
					defer conn.Close()
					_, _ = io.WriteString(conn, "ok")
				}
			}()
			dialTimeout := 8 * time.Second
			if test.blackholeFirst {
				dialTimeout = 20 * time.Second
			}
			dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
			defer cancel()
			conn, err := endpoint.DialContext(dialCtx, N.NetworkTCP, M.ParseSocksaddrHostPort("10.77.0.1", uint16(listener.Addr().(*net.TCPAddr).Port)))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			deadline, _ := dialCtx.Deadline()
			if err = conn.SetReadDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if data, err := io.ReadAll(conn); err != nil || string(data) != "ok" {
				t.Fatalf("TCP through WARP returned %q, %v", data, err)
			}
			testWARPUDP(t, dialCtx, endpoint)
			link, err := netlink.LinkByName("warp-test")
			if err != nil {
				t.Fatal(err)
			}
			if link.Type() != test.kind {
				t.Fatalf("WARP link has kind %q, want %q", link.Type(), test.kind)
			}
			if test.blackholeFirst || test.system {
				select {
				case packet := <-firstPacket:
					if test.blackholeFirst && (len(packet) < obfuscation.JMin || len(packet) > obfuscation.JMax) {
						t.Fatalf("replacement detour began with a %d-byte packet, want AmneziaWG junk", len(packet))
					}
					if test.system && !bytes.Equal(packet, []byte{0xde, 0xad, 0xbe, 0xef}) {
						t.Fatalf("userspace detour began with a %d-byte packet, want the AmneziaWG signature", len(packet))
					}
				default:
					t.Fatal("detour sent no packet")
				}
			}
		})
	}
}

type warpTestDetour struct {
	outbound.Adapter
	peer           M.Socksaddr
	blackholeFirst bool
	dials          atomic.Int32
	firstPacket    chan []byte
}

func (d *warpTestDetour) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != N.NetworkUDP || destination != d.peer {
		return nil, fmt.Errorf("unexpected WARP detour destination %s %s", network, destination)
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, network, M.ParseSocksaddrHostPort("127.0.0.1", d.peer.Port).String())
	if err != nil {
		return nil, err
	}
	return &warpTestDetourConn{
		Conn: conn, discard: d.blackholeFirst && d.dials.Add(1) == 1, firstPacket: d.firstPacket,
	}, nil
}

func (d *warpTestDetour) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("expected a connected WARP UDP detour")
}

type warpTestDetourConn struct {
	net.Conn
	discard     bool
	firstPacket chan []byte
}

func (c *warpTestDetourConn) Write(packet []byte) (int, error) {
	if c.discard {
		return len(packet), nil
	}
	if c.firstPacket != nil {
		select {
		case c.firstPacket <- bytes.Clone(packet):
		default:
		}
		c.firstPacket = nil
	}
	return c.Conn.Write(packet)
}

func testWARPUDP(t *testing.T, ctx context.Context, endpoint adapter.Endpoint) {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		var buffer [16]byte
		count, from, err := server.ReadFromUDP(buffer[:])
		if err == nil {
			_, _ = server.WriteToUDP(buffer[:count], from)
		}
	}()
	destination := M.ParseSocksaddrHostPort("10.77.0.1", uint16(server.LocalAddr().(*net.UDPAddr).Port))
	packet, err := endpoint.ListenPacket(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	deadline, _ := ctx.Deadline()
	if err = packet.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if _, err = packet.WriteTo([]byte("ok"), destination.UDPAddr()); err != nil {
		t.Fatal(err)
	}
	var buffer [16]byte
	count, _, err := packet.ReadFrom(buffer[:])
	if err != nil || string(buffer[:count]) != "ok" {
		t.Fatalf("UDP through WARP returned %q, %v", buffer[:count], err)
	}
}

func warpTestKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func seedWARPTestProfile(t *testing.T, ctx context.Context, options option.CacheFileOptions, clientKey, serverKey wgtypes.Key, port int) {
	t.Helper()
	config := warp.Config{PrivateKey: clientKey.String()}
	config.Interface.Addresses.V4 = " 10.77.0.2 "
	config.Interface.Addresses.V6 = " fd77::2 "
	var peer cloudflare.Peer
	peer.PublicKey = " " + serverKey.String() + " "
	peer.Endpoint.Host = "127.0.0.1"
	peer.Endpoint.Ports = []int{port}
	config.Peers = append(config.Peers, peer)
	content, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	logger := log.NewNOPFactory().NewLogger("warp-test-cache")
	cache := cachefile.New(ctx, logger, options)
	scope := adapter.NewScope(ctx, logger)
	defer scope.Close()
	if err = scope.Start("warp-test-cache", cache, adapter.StartStateInitialize); err != nil {
		t.Fatal(err)
	}
	if err = cache.SaveWARPConfig("warp", &adapter.SavedBinary{Content: content, LastUpdated: time.Now()}); err != nil {
		t.Fatal(err)
	}
}
