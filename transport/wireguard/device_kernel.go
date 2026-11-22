package wireguard

import (
	"errors"

	N "github.com/sagernet/sing/common/network"
)

var errKernelUnavailable = errors.New("kernel WireGuard is unavailable")

type kernelDevice interface {
	N.Dialer
	Close() error
	SetUp(up bool) error
	BindUpdate() error
}
