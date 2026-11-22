package option

import (
	"slices"
	"testing"

	"github.com/sagernet/sing/common/json"
)

func TestAutodetectOptionsPorts(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		content string
		ports   []uint16
		invalid bool
	}{
		{name: "omitted", content: `{}`},
		{name: "single", content: `{"ports":8443}`, ports: []uint16{8443}},
		{name: "multiple", content: `{"ports":[443,8443,65535]}`, ports: []uint16{443, 8443, 65535}},
		{name: "negative", content: `{"ports":[-1]}`, invalid: true},
		{name: "overflow", content: `{"ports":[65536]}`, invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var options AutodetectOptions
			err := json.Unmarshal([]byte(test.content), &options)
			if (err != nil) != test.invalid {
				t.Fatalf("unexpected decode error: %v", err)
			}
			if !test.invalid && !slices.Equal(options.Ports, test.ports) {
				t.Fatalf("ports = %v, want %v", options.Ports, test.ports)
			}
		})
	}
}
