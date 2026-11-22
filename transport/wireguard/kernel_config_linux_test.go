//go:build linux && !android

package wireguard

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/sagernet/netlink"
)

func TestKernelAmneziaJunkRange(t *testing.T) {
	config := kernelConfig{family: &netlink.GenlFamily{Version: 3, MaxAttr: kernelNoCookies}}
	for _, test := range []struct {
		name     string
		minimum  int
		maximum  int
		wantMin  uint16
		wantMax  uint16
		fallback bool
	}{
		{name: "ordered", minimum: 40, maximum: 64, wantMin: 40, wantMax: 64},
		{name: "only minimum", minimum: 40, wantMax: 40},
		{name: "only maximum", maximum: 40, wantMax: 40},
		{name: "reversed", minimum: 64, maximum: 40, wantMin: 40, wantMax: 64},
		{name: "zero length", fallback: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			attrs, err := config.amneziaAttributes(&AmneziaOptions{
				JC:   2,
				JMin: test.minimum,
				JMax: test.maximum,
			})
			if test.fallback {
				if !errors.Is(err, errKernelUnavailable) {
					t.Fatalf("expected userspace fallback, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			values := make(map[uint16]uint16, len(attrs))
			for _, attr := range attrs {
				values[attr.Type] = binary.NativeEndian.Uint16(attr.Data)
			}
			if values[kernelJc] != 2 || values[kernelJmin] != test.wantMin || values[kernelJmax] != test.wantMax {
				t.Fatalf(
					"encoded junk count and bounds = %d, %d..%d, want 2, %d..%d",
					values[kernelJc], values[kernelJmin], values[kernelJmax], test.wantMin, test.wantMax,
				)
			}
		})
	}
}
