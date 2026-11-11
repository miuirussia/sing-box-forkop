//go:build linux && !android

package device

import (
	"testing"

	"github.com/sagernet/wireguard-go/conn"
)

type routeListenerBind struct{ conn.Bind }

func (b routeListenerBind) Upstream() any { return b.Bind }

func TestStartRouteListenerWrappedBind(t *testing.T) {
	standard := conn.NewStdNetBind(nil)
	for _, test := range []struct {
		name string
		bind conn.Bind
		want bool
	}{
		{"standard", standard, true},
		{"wrapped standard", routeListenerBind{standard}, true},
		{"nested standard", routeListenerBind{routeListenerBind{standard}}, true},
		{"non-standard", routeListenerBind{}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			device := new(Device)
			cancel, err := device.startRouteListener(test.bind)
			if err != nil {
				t.Fatal(err)
			}
			if cancel != nil {
				defer cancel.Cancel()
			}
			if (cancel != nil) != test.want {
				t.Fatalf("route listener started = %v, want %v", cancel != nil, test.want)
			}
		})
	}
}
