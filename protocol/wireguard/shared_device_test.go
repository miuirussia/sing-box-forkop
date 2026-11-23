package wireguard

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/phobos"
	"github.com/sagernet/sing-box/transport/wireguard"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// WARP builds its WireGuard endpoints from goroutines, so the first lookups of
// a box can race; they must still agree on one registry, and a registry must
// never outlive or cross into another box.
func TestDeviceRegistryIsOnePerBox(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	registries := make([]*deviceRegistry, 16)
	var group sync.WaitGroup
	for i := range registries {
		group.Add(1)
		go func() {
			defer group.Done()
			registries[i] = deviceRegistryFromContext(ctx)
		}()
	}
	group.Wait()
	for _, registry := range registries {
		require.Same(t, registries[0], registry)
	}
	require.NotSame(t, registries[0], deviceRegistryFromContext(service.ContextWithDefaultRegistry(context.Background())))
	require.Nil(t, deviceRegistryFromContext(context.Background()))
}

func sampleDeviceConfiguration() deviceConfiguration {
	return deviceConfiguration{
		Type: "amneziawg",
		Options: option.WireGuardCommonOptions{
			DialerOptions: option.DialerOptions{Detour: "proxy"},
			Kernel:        true,
			MTU:           1280,
			Address:       badoption.Listable[netip.Prefix]{netip.MustParsePrefix("10.8.1.5/32")},
			PrivateKey:    "client-key",
			Peers: []option.WireGuardPeer{{
				Address:    "203.0.113.1",
				Port:       51820,
				PublicKey:  "server-key",
				AllowedIPs: badoption.Listable[netip.Prefix]{netip.MustParsePrefix("0.0.0.0/0")},
			}},
		},
		Amnezia: &wireguard.AmneziaOptions{JC: 5, S4: 12},
	}
}

// The key decides which endpoints run on one device, so every setting of the
// device has to reach it; an option type that serialised only part of itself
// would merge endpoints that are not the same.
func TestSharedDeviceKeyCoversEverySetting(t *testing.T) {
	config := sampleDeviceConfiguration()
	base, identities, err := config.key()
	require.NoError(t, err)
	require.Equal(t, []string{"client-key/server-key"}, identities)

	again, _, err := config.key()
	require.NoError(t, err)
	require.Equal(t, base, again)

	for name, change := range map[string]func(*deviceConfiguration){
		"type":          func(c *deviceConfiguration) { c.Type = "wireguard" },
		"kernel":        func(c *deviceConfiguration) { c.Options.Kernel = false },
		"kernel detour": func(c *deviceConfiguration) { c.KernelDetour = true },
		"mtu":           func(c *deviceConfiguration) { c.Options.MTU = 1420 },
		"address":       func(c *deviceConfiguration) { c.Options.Address[0] = netip.MustParsePrefix("10.8.1.6/32") },
		"private key":   func(c *deviceConfiguration) { c.Options.PrivateKey = "other-client-key" },
		"detour":        func(c *deviceConfiguration) { c.Options.Detour = "other-proxy" },
		"bind interface": func(c *deviceConfiguration) {
			c.Options.BindInterface = "wan"
		},
		"peer address": func(c *deviceConfiguration) { c.Options.Peers[0].Address = "203.0.113.2" },
		"peer key":     func(c *deviceConfiguration) { c.Options.Peers[0].PublicKey = "other-server-key" },
		"obfuscation":  func(c *deviceConfiguration) { c.Amnezia.S4 = 16 },
	} {
		t.Run(name, func(t *testing.T) {
			changedConfig := sampleDeviceConfiguration()
			change(&changedConfig)
			changed, _, err := changedConfig.key()
			require.NoError(t, err)
			require.NotEqual(t, base, changed)
		})
	}
}

func TestPhobosDeviceIdentity(t *testing.T) {
	config := deviceConfiguration{Type: "phobos", Phobos: &phobos.Options{Key: "first", Masking: "STUN"}}
	base, _, err := config.key()
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range []*phobos.Options{{Key: "second", Masking: "STUN"}, {Key: "first", Masking: "MEDIA"}, {Key: "first", Masking: "STUN", ObfuscateBytes: 16}} {
		config.Phobos = changed
		key, _, err := config.key()
		if err != nil || key == base {
			t.Fatalf("different Phobos settings share a device: %v", err)
		}
	}
}
