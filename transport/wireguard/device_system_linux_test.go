//go:build linux && !android && with_gvisor

package wireguard

import (
	"net/netip"
	"runtime"
	"sync"
	"testing"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"

	"golang.org/x/sys/unix"
)

type systemTestMonitor struct{ tun.DefaultInterfaceMonitor }

func (systemTestMonitor) RegisterMyInterface(string) {}

type systemTestNetworkManager struct {
	adapter.NetworkManager
	finder control.InterfaceFinder
}

func (m systemTestNetworkManager) InterfaceFinder() control.InterfaceFinder { return m.finder }
func (systemTestNetworkManager) InterfaceMonitor() tun.DefaultInterfaceMonitor {
	return systemTestMonitor{}
}
func (systemTestNetworkManager) DefaultOptions() adapter.NetworkOptions {
	return adapter.NetworkOptions{}
}
func (systemTestNetworkManager) AutoDetectInterface() bool                { return false }
func (systemTestNetworkManager) AutoRedirectOutputMarkFunc() control.Func { return nil }

func testSystemRulesRemoved(t *testing.T, client *Endpoint, name string) {
	t.Helper()
	rules, err := netlink.RuleList(unix.AF_INET)
	if err != nil {
		t.Fatal(err)
	}
	var table int
	for _, rule := range rules {
		if rule.OifName == name {
			table = rule.Table
			break
		}
	}
	if table == 0 {
		t.Fatal("system TUN has no IPv4 output interface rule")
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	rules, err = netlink.RuleList(unix.AF_INET)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		if rule.Table == table {
			t.Fatalf("system TUN routing rule left behind: %v", rule)
		}
	}
}

type testBatchTUN struct{ tun.LinuxTUN }

func (testBatchTUN) BatchWrite(packets [][]byte, offset int) (int, error) {
	runtime.Gosched()
	return len(packets), nil
}

func TestSystemTUNConcurrentWrites(t *testing.T) {
	device := &systemStackDevice{systemDevice: &systemDevice{
		options:     DeviceOptions{Address: []netip.Prefix{netip.MustParsePrefix("10.77.0.2/32")}},
		batchDevice: testBatchTUN{},
	}}
	var workers sync.WaitGroup
	for range 2 {
		workers.Go(func() {
			packet := make([]byte, 20)
			packet[0] = 0x45
			copy(packet[16:20], []byte{10, 77, 0, 2})
			for range 100 {
				if count, err := device.Write([][]byte{packet}, 0); err != nil || count != 1 {
					t.Errorf("write returned %d, %v", count, err)
					return
				}
			}
		})
	}
	workers.Wait()
}
