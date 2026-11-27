//go:build !linux

package tlsspoof

import (
	"fmt"
	"net"
)

type UDPInjector struct{}

func NewUDPInjector(any, net.Addr) (*UDPInjector, error) {
	return nil, fmt.Errorf("desync: ephemeral raw UDP fake sockets require Linux with CAP_NET_RAW")
}
func (*UDPInjector) Send([]byte, int) error { return fmt.Errorf("desync: raw UDP requires Linux") }
func (*UDPInjector) Close() error           { return nil }
