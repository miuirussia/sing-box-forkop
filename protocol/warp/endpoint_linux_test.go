//go:build linux && !android && with_wireguard && with_gvisor

package warp_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/cloudflare"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/warp"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestWARPLinuxBackends(t *testing.T) {
	if os.Getenv("SING_BOX_TEST_KERNEL_WIREGUARD") == "" {
		t.Skip("set SING_BOX_TEST_KERNEL_WIREGUARD inside a Linux network namespace with CAP_NET_ADMIN")
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
	for _, test := range []struct {
		name    string
		kind    string
		system  bool
		detour  string
		amnezia *option.OneSidedAmnezia
	}{
		{name: "plain kernel", kind: C.TypeWireGuard},
		{name: "obfuscated kernel", kind: C.TypeAmneziaWG, amnezia: obfuscation},
		{name: "system fallback through detour", kind: "tuntap", system: true, detour: "direct", amnezia: obfuscation},
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
			instance, err := box.New(box.Options{Context: ctx, Options: option.Options{
				Log:          &option.LogOptions{Level: "warn"},
				Experimental: &option.ExperimentalOptions{CacheFile: &cacheOptions},
				Endpoints: []option.Endpoint{
					{Type: C.TypeWireGuard, Tag: "server", Options: &option.WireGuardEndpointOptions{WireGuardCommonOptions: option.WireGuardCommonOptions{
						PrivateKey: serverKey.String(), ListenPort: uint16(port), Address: []netip.Prefix{netip.MustParsePrefix("10.77.0.1/32")},
						Peers: []option.WireGuardPeer{{PublicKey: clientKey.PublicKey().String(), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.77.0.2/32")}}},
					}}},
					{Type: C.TypeWARP, Tag: "warp", Options: &option.WARPEndpointOptions{
						Kernel: true, System: test.system, Name: "warp-test", Amnezia: test.amnezia,
						DialerOptions: option.DialerOptions{Detour: test.detour},
					}},
				},
				Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{}}},
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
			dialCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
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
		})
	}
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
