//go:build !linux

package tlsspoof

import (
	"fmt"
	"net"
)

type DesyncSession struct{}

func newDesyncSession(net.Conn) (*DesyncSession, error) {
	return nil, fmt.Errorf("desync: raw TCP requires Linux with CAP_NET_RAW and CAP_NET_ADMIN")
}
func (*DesyncSession) Send(DesyncPacket) error { return fmt.Errorf("desync: raw TCP requires Linux") }
func (*DesyncSession) Close() error            { return nil }
