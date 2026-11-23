//go:build linux && !android && with_gvisor

package wireguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/phobos"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
)

func TestNativeWireGuardBindHonorsDialerOptions(t *testing.T) {
	obfuscation, err := phobos.Normalize(&option.PhobosObfuscationOptions{Key: "test", Masking: "NONE"})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		phobos *phobos.Options
	}{{name: "WireGuard"}, {name: "Phobos", phobos: obfuscation}} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			if err = server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			peer := server.LocalAddr().(*net.UDPAddr).AddrPort()
			source := netip.MustParseAddr("127.0.0.2")
			bindAddress := badoption.Addr(source)
			options := option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{Inet4BindAddress: &bindAddress}}
			direct, err := dialer.NewDefault(ctx, options)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := &Endpoint{
				options: EndpointOptions{Context: ctx, Logger: logger.NOP(), Dialer: direct, Phobos: test.phobos},
				peers:   []peerConfig{{endpoint: peer}},
			}
			bind, _ := endpoint.createBind()
			_, port, err := bind.Open(0)
			if err != nil {
				t.Fatal(err)
			}
			defer bind.Close()
			remote, err := bind.ParseEndpoint(peer.String())
			if err != nil {
				t.Fatal(err)
			}
			if err = bind.Send([][]byte{{1, 0, 0, 0}}, remote, 0); err != nil {
				t.Fatal(err)
			}
			_, sender, err := server.ReadFromUDPAddrPort(make([]byte, 1024))
			if err != nil {
				t.Fatal(err)
			}
			if sender != netip.AddrPortFrom(source, port) {
				t.Fatalf("sent from %v, want %v:%d", sender, source, port)
			}

			options.NetNs = filepath.Join(t.TempDir(), "missing")
			endpoint.options.Dialer, err = dialer.NewDefault(ctx, options)
			if err != nil {
				t.Fatal(err)
			}
			bind, _ = endpoint.createBind()
			defer bind.Close()
			if _, _, err = bind.Open(0); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("open in a missing namespace returned %v", err)
			}
		})
	}
}
