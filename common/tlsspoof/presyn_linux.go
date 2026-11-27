package tlsspoof

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"golang.org/x/sys/unix"
)

// InjectSYNPayload sends an invalid-checksum SYN before the kernel's real SYN.
// It binds the real socket first, so both packets share routing and a TCP tuple.
// The fake is never queued in TCP, and cannot be accepted even on a short path.
// This is a fake handshake packet, not TCP Fast Open application data.
func InjectSYNPayload(tcpSocket int, dst netip.AddrPort, source netip.Addr, payload []byte, ttl int) error {
	if len(payload) == 0 || len(payload) > 1200 {
		return fmt.Errorf("desync: syndata must contain 1..1200 bytes")
	}
	if dst.Addr().Zone() != "" {
		return fmt.Errorf("desync: syndata does not support scoped IPv6 destinations")
	}
	src, err := bindSYNSource(tcpSocket, dst, source)
	if err != nil {
		return err
	}
	fd, target, err := openLinuxRawSocket(dst)
	if err != nil {
		return fmt.Errorf("desync: syndata requires CAP_NET_RAW: %w", err)
	}
	defer unix.Close(fd)
	if err = inheritRouting(fd, tcpSocket, src); err != nil {
		return err
	}
	var random [4]byte
	if _, err = rand.Read(random[:]); err != nil {
		return err
	}
	frame := buildTCPSegment(src, dst, spoofPacketInfo{seqNum: binary.BigEndian.Uint32(random[:])}, payload)
	ipLength := 20
	if dst.Addr().Is6() {
		ipLength = 40
	}
	frame[ipLength+13] = byte(header.TCPFlagSyn)
	if ttl == 0 {
		ttl = 3
	}
	if dst.Addr().Is4() {
		frame[8] = byte(ttl)
		ip := header.IPv4(frame[:ipLength])
		ip.SetChecksum(0)
		ip.SetChecksum(^ip.CalculateChecksum())
	} else {
		frame[7] = byte(ttl)
	}
	tcp := header.TCP(frame[ipLength:])
	tcp.SetChecksum(0)
	applyTCPChecksum(tcp, src.Addr(), dst.Addr(), payload, true)
	if err = unix.Sendto(fd, frame, 0, target); err != nil {
		return fmt.Errorf("desync: inject fake SYN: %w", err)
	}
	return nil
}

func bindSYNSource(tcpSocket int, dst netip.AddrPort, preferred netip.Addr) (netip.AddrPort, error) {
	sa, err := unix.Getsockname(tcpSocket)
	if err != nil {
		return netip.AddrPort{}, err
	}
	var source netip.AddrPort
	var family int
	switch local := sa.(type) {
	case *unix.SockaddrInet4:
		source = netip.AddrPortFrom(netip.AddrFrom4(local.Addr), uint16(local.Port))
		family = unix.AF_INET
	case *unix.SockaddrInet6:
		source = netip.AddrPortFrom(netip.AddrFrom16(local.Addr), uint16(local.Port))
		family = unix.AF_INET6
	default:
		return netip.AddrPort{}, fmt.Errorf("desync: syndata requires an IP TCP socket")
	}
	if preferred.IsValid() {
		preferred = preferred.Unmap()
		if preferred.Is4() != dst.Addr().Is4() {
			return netip.AddrPort{}, fmt.Errorf("desync: SYN source address family does not match destination")
		}
		source = netip.AddrPortFrom(preferred, source.Port())
	}
	if source.Addr().IsUnspecified() {
		// connect() on a UDP socket discovers the route's source address without
		// transmitting anything. Preserve the original socket's mark and device.
		probe, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
		if err != nil {
			return netip.AddrPort{}, err
		}
		defer unix.Close(probe)
		if err = inheritRouting(probe, tcpSocket, netip.AddrPortFrom(source.Addr(), 0)); err != nil {
			return netip.AddrPort{}, err
		}
		var target unix.Sockaddr
		if family == unix.AF_INET {
			target = &unix.SockaddrInet4{Addr: dst.Addr().As4(), Port: int(dst.Port())}
		} else {
			target = &unix.SockaddrInet6{Addr: dst.Addr().As16(), Port: int(dst.Port())}
		}
		if err = unix.Connect(probe, target); err != nil {
			return netip.AddrPort{}, err
		}
		bound, err := unix.Getsockname(probe)
		if err != nil {
			return netip.AddrPort{}, err
		}
		switch actual := bound.(type) {
		case *unix.SockaddrInet4:
			source = netip.AddrPortFrom(netip.AddrFrom4(actual.Addr), source.Port())
		case *unix.SockaddrInet6:
			source = netip.AddrPortFrom(netip.AddrFrom16(actual.Addr), source.Port())
		}
	}
	if source.Port() == 0 {
		// An early bind without a port is incompatible with constructing the
		// fake tuple; allocate its port now, before the kernel emits the SYN.
		if err = unix.SetsockoptInt(tcpSocket, unix.IPPROTO_IP, unix.IP_BIND_ADDRESS_NO_PORT, 0); err != nil {
			return netip.AddrPort{}, err
		}
		if family == unix.AF_INET {
			err = unix.Bind(tcpSocket, &unix.SockaddrInet4{Addr: source.Addr().As4()})
		} else {
			var zone uint32
			if source.Addr().Zone() != "" {
				iface, err := net.InterfaceByName(source.Addr().Zone())
				if err != nil {
					return netip.AddrPort{}, err
				}
				zone = uint32(iface.Index)
			}
			err = unix.Bind(tcpSocket, &unix.SockaddrInet6{Addr: source.Addr().As16(), ZoneId: zone})
		}
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("desync: bind SYN tuple: %w", err)
		}
		bound, err := unix.Getsockname(tcpSocket)
		if err != nil {
			return netip.AddrPort{}, err
		}
		switch actual := bound.(type) {
		case *unix.SockaddrInet4:
			source = netip.AddrPortFrom(source.Addr(), uint16(actual.Port))
		case *unix.SockaddrInet6:
			source = netip.AddrPortFrom(source.Addr(), uint16(actual.Port))
		}
	}
	return source, nil
}
