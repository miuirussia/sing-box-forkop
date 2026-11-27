package desync

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
)

// SocketControl is composed with the normal dialer controls before connect.
// Unsupported SYN features are rejected before a socket sends any traffic.
func SocketControl(o option.DesyncOptions) (control.Func, error) {
	if err := Validate(o); err != nil {
		return nil, err
	}
	return preSYNControl(o)
}
