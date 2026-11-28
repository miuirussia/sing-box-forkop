package desync

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
)

type partitionNetwork struct {
	adapter.NetworkManager
	fingerprint uint64
}

func (n partitionNetwork) NetworkEnvironment() uint64 { return n.fingerprint }
func (n partitionNetwork) NetworkInterfaces() []adapter.NetworkInterface {
	return []adapter.NetworkInterface{{Interface: control.Interface{Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}}}}
}

func TestManualStrategyDiagnostics(t *testing.T) {
	options := strategyForTest(t, `{"mode":"split","split_pos":"1","delay":"5ms"}`)
	out := &Outbound{options: options}
	stats := out.DesyncStats()
	if stats.Version != 1 || stats.Current != strategyID(options) || stats.Reason != "manual strategy" {
		t.Fatalf("manual strategy diagnostics omitted the full identity: %+v", stats)
	}
}

func TestAdaptiveRouteUpdateAndRestart(t *testing.T) {
	for _, fingerprint := range []uint64{0, 12345} {
		name := "interface_fallback"
		if fingerprint != 0 {
			name = "manager_fingerprint"
		}
		t.Run(name, func(t *testing.T) {
			store := new(memoryStore)
			open := func() *Outbound {
				a := adaptiveForTest(t)
				a.store = store
				if err := a.Load(); err != nil {
					t.Fatal(err)
				}
				return &Outbound{networkManager: partitionNetwork{fingerprint: fingerprint}, adaptive: a}
			}
			first := open()
			destination := M.ParseSocksaddr("example.com:443")
			learn := func(out *Outbound, mode string) {
				for _, candidate := range out.adaptive.catalog {
					if candidate.Mode == mode {
						out.adaptive.observe(destinationKeys(destination, out.networkPartition()), strategyID(candidate), "response", true, time.Millisecond)
						break
					}
				}
				if err := out.adaptive.Flush(); err != nil {
					t.Fatal(err)
				}
			}
			winner := func(out *Outbound) string {
				return out.adaptive.ranked(destinationKeys(destination, out.networkPartition()))[0].Mode
			}
			learn(first, "tlsrec")
			if err := first.adaptive.Close(); err != nil {
				t.Fatal(err)
			}
			current := open()
			if winner(current) != "tlsrec" {
				t.Fatal("ordinary restart discarded learned strategy")
			}
			previous := current.networkPartition()
			current.InterfaceUpdated(context.Background())
			if current.networkPartition() == previous || winner(current) == "tlsrec" {
				t.Fatal("route update reused the old strategy with an unchanged network fingerprint")
			}
			if err := current.adaptive.Close(); err != nil {
				t.Fatal(err)
			}
			current = open()
			if current.networkPartition() == previous || winner(current) == "tlsrec" {
				t.Fatal("restart before new observations resurrected pre-update learning")
			}
			learn(current, "multi_split")
			if err := current.adaptive.Close(); err != nil {
				t.Fatal(err)
			}
			restarted := open()
			if restarted.networkPartition() != current.networkPartition() || winner(restarted) != "multi_split" {
				t.Fatal("restart failed to restore learning from the updated route")
			}
		})
	}
}
