//go:build linux || darwin

package desync

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"syscall"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

func withUDPTTL(conn any, destination net.Addr, ttl int, send func([]byte) (int, error), burst func(func([]byte) (int, error)) error) (err error) {
	if ttl == 0 {
		return burst(send)
	}
	sc, ok := common.Cast[syscall.Conn](conn)
	if !ok {
		return fmt.Errorf("desync: UDP TTL requires an owned UDP socket")
	}
	addr := M.AddrPortFromNet(destination)
	if udp, ok := destination.(*net.UDPAddr); ok {
		addr = udp.AddrPort()
	}
	if !addr.IsValid() {
		return fmt.Errorf("desync: UDP TTL requires a resolved destination")
	}
	level, name := unix.IPPROTO_IP, unix.IP_TTL
	if addr.Addr().Unmap().Is6() {
		level, name = unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS
	}
	if runtime.GOOS == "darwin" {
		var v6 bool
		if err := control.Conn(sc, func(raw uintptr) error {
			sa, err := unix.Getsockname(int(raw))
			_, v6 = sa.(*unix.SockaddrInet6)
			return err
		}); err != nil {
			return err
		}
		if v6 {
			// Darwin's socket hop-limit option also changes mapped IPv4 TTL.
			// Restoring its default -1 makes subsequent IPv4 packets use TTL255.
			// Native IPv6 supports per-message hops without mutating either default;
			// mapped IPv4 ignores ancillary TTL and must fail before sending a fake.
			if addr.Addr().Unmap().Is4() {
				return fmt.Errorf("desync: Darwin cannot safely restore IPv4 fake TTL on a dual-stack socket; use an IPv4 UDP socket")
			}
			udp, ok := common.Cast[*net.UDPConn](conn)
			if !ok {
				return fmt.Errorf("desync: Darwin IPv6 fake hop limit requires an owned UDP socket")
			}
			target := M.SocksaddrFromNet(destination).UDPAddr()
			if udp.RemoteAddr() != nil {
				target = nil
			}
			oob := (&ipv6.ControlMessage{HopLimit: ttl}).Marshal()
			return burst(func(p []byte) (int, error) { n, _, err := udp.WriteMsgUDP(p, oob, target); return n, err })
		}
	}
	var original int
	err = control.Conn(sc, func(raw uintptr) error {
		var e error
		original, e = unix.GetsockoptInt(int(raw), level, name)
		if e != nil {
			return e
		}
		return unix.SetsockoptInt(int(raw), level, name, ttl)
	})
	if err != nil {
		return fmt.Errorf("desync: set UDP TTL: %w", err)
	}
	defer func() {
		restore := control.Conn(sc, func(raw uintptr) error { return unix.SetsockoptInt(int(raw), level, name, original) })
		if restore != nil && !errors.Is(restore, net.ErrClosed) {
			err = errors.Join(err, fmt.Errorf("desync: restore UDP TTL: %w", restore))
		}
	}()
	return burst(send)
}
