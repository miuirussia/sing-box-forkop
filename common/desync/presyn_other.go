//go:build !linux

package desync

import (
	"fmt"
	"net"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
)

func validatePreSYN(o option.DesyncOptions) error {
	if o.SynData != "" || o.WScale != 0 || o.WScaleExplicit || o.AutoTTL {
		return fmt.Errorf("desync: SYN data, window scaling and route observation require Linux")
	}
	return nil
}

func preSYNControl(o option.DesyncOptions) (control.Func, error) {
	return nil, validatePreSYN(o)
}

func observedConnectionTTL(net.Conn) (int, bool) { return 0, false }

func restoreScaleBuffer(net.Conn) error { return nil }
