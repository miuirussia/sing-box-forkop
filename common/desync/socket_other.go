//go:build !linux && !darwin

package desync

import (
	"fmt"
	"net"
)

func withUDPTTL(_ any, _ net.Addr, ttl int, send func([]byte) (int, error), burst func(func([]byte) (int, error)) error) error {
	if ttl != 0 {
		return fmt.Errorf("desync: UDP TTL requires Linux or Darwin")
	}
	return burst(send)
}
