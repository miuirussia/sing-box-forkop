package tlsspoof

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/sys/unix"
)

// UDPInjector is a send-only raw socket; it cannot steal replies from the real
// UDP session. Closing it preserves the application's local port and socket.
type UDPInjector struct {
	mtu      int
	mu       sync.Mutex
	fd       int
	src, dst netip.AddrPort
	target   unix.Sockaddr
}

func NewUDPInjector(conn any, addr net.Addr) (*UDPInjector, error) {

	dst := M.AddrPortFromNet(addr)
	if destination, ok := addr.(*net.UDPAddr); ok {
		dst = destination.AddrPort()
	}
	if !dst.IsValid() {
		return nil, fmt.Errorf("desync: raw UDP fake needs a resolved destination; apply domain NAT outside the desync engine")
	}
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())

	if !dst.IsValid() || dst.Addr().Zone() != "" {
		return nil, fmt.Errorf("desync: raw UDP fake needs an unscoped IPv4/IPv6 destination")
	}
	sc, ok := common.Cast[syscall.Conn](conn)
	if !ok {
		return nil, fmt.Errorf("desync: udp_keep_socket=false requires an owned UDP socket")
	}
	injector := &UDPInjector{fd: -1, dst: dst}
	err := control.Conn(sc, func(raw uintptr) error {
		base := int(raw)
		return inSocketNamespace(base, func() error {
			sa, err := unix.Getsockname(base)
			if err != nil {
				return err
			}
			var ip netip.Addr
			var port int
			switch local := sa.(type) {
			case *unix.SockaddrInet4:
				ip = netip.AddrFrom4(local.Addr)
				port = local.Port
			case *unix.SockaddrInet6:
				ip = netip.AddrFrom16(local.Addr).Unmap()
				port = local.Port
			default:
				return fmt.Errorf("desync: raw UDP fake requires an IP socket")
			}
			if port == 0 {
				return fmt.Errorf("desync: raw UDP session has no assigned local port")
			}
			family := unix.AF_INET
			if dst.Addr().Is6() {
				family = unix.AF_INET6
			}
			{
				probe, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
				if err != nil {
					return err
				}
				defer unix.Close(probe)
				unspecified := netip.IPv4Unspecified()
				if family == unix.AF_INET6 {
					unspecified = netip.IPv6Unspecified()
				}

				routeSource := unspecified
				if !ip.IsUnspecified() && ip.Is4() == dst.Addr().Is4() {
					routeSource = ip
				}
				if err = inheritRouting(probe, base, netip.AddrPortFrom(routeSource, 0)); err != nil {
					return err
				}
				var target unix.Sockaddr
				if family == unix.AF_INET {
					target = &unix.SockaddrInet4{Addr: dst.Addr().As4(), Port: int(dst.Port())}
				} else {
					target = &unix.SockaddrInet6{Addr: dst.Addr().As16(), Port: int(dst.Port())}
				}
				if err = unix.Connect(probe, target); err != nil {
					return err
				}

				level, name := unix.IPPROTO_IP, unix.IP_MTU
				if family == unix.AF_INET6 {
					level, name = unix.IPPROTO_IPV6, unix.IPV6_MTU
				}
				injector.mtu, err = unix.GetsockoptInt(probe, level, name)
				if err != nil {
					return fmt.Errorf("desync: raw UDP path MTU: %w", err)
				}
				local, err := unix.Getsockname(probe)
				if err != nil {
					return err
				}
				switch a := local.(type) {
				case *unix.SockaddrInet4:
					ip = netip.AddrFrom4(a.Addr)
				case *unix.SockaddrInet6:
					ip = netip.AddrFrom16(a.Addr).Unmap()
				}
			}
			if ip.Is4() != dst.Addr().Is4() {
				return fmt.Errorf("desync: raw UDP address family mismatch")
			}
			injector.src = netip.AddrPortFrom(ip, uint16(port))
			fd, err := unix.Socket(family, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.IPPROTO_UDP)
			if err != nil {
				return fmt.Errorf("desync: udp_keep_socket=false raw fake needs CAP_NET_RAW: %w", err)
			}
			injector.fd = fd
			if family == unix.AF_INET {
				err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
				injector.target = &unix.SockaddrInet4{Addr: dst.Addr().As4()}
			} else {
				err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1)
				injector.target = &unix.SockaddrInet6{Addr: dst.Addr().As16()}
			}
			if err != nil {
				return err
			}
			return inheritRouting(fd, base, injector.src)
		})
	})
	if err != nil {
		injector.Close()
		return nil, err
	}
	return injector, nil
}
func (u *UDPInjector) Send(payload []byte, ttl int) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.fd < 0 {
		return net.ErrClosed
	}
	if len(payload) > 65507 {
		return fmt.Errorf("desync: raw UDP fake exceeds datagram size")
	}
	if ttl == 0 {
		ttl = 64
	}
	iplen := 20
	if u.src.Addr().Is6() {
		iplen = 40
	}
	frame := make([]byte, iplen+8+len(payload))
	udp := frame[iplen:]
	binary.BigEndian.PutUint16(udp, u.src.Port())
	binary.BigEndian.PutUint16(udp[2:], u.dst.Port())
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], payload)
	if iplen == 20 {
		frame[0] = 0x45
		binary.BigEndian.PutUint16(frame[2:], uint16(len(frame)))
		binary.BigEndian.PutUint16(frame[4:], uint16(fragmentID.Add(1)))
		frame[8] = byte(ttl)
		frame[9] = 17
		copy(frame[12:], u.src.Addr().AsSlice())
		copy(frame[16:], u.dst.Addr().AsSlice())
		ip := header.IPv4(frame[:20])
		ip.SetChecksum(^ip.CalculateChecksum())
	} else {
		frame[0] = 0x60
		binary.BigEndian.PutUint16(frame[4:], uint16(len(udp)))
		frame[6] = 17
		frame[7] = byte(ttl)
		copy(frame[8:], u.src.Addr().AsSlice())
		copy(frame[24:], u.dst.Addr().AsSlice())
	}
	pseudo := header.PseudoHeaderChecksum(header.UDPProtocolNumber, u.src.Addr().AsSlice(), u.dst.Addr().AsSlice(), uint16(len(udp)))
	sum := ^checksum.Checksum(udp, pseudo)
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:], sum)
	frames := [][]byte{frame}
	if u.mtu > 0 && len(frame) > u.mtu {
		overhead := iplen
		if iplen == 40 {
			overhead += 8
		}
		var err error
		frames, err = fragmentFrames(frame, (u.mtu-overhead)&^7)
		if err != nil {
			return err
		}
	}
	for _, part := range frames {
		if err := unix.Sendto(u.fd, part, 0, u.target); err != nil {
			return fmt.Errorf("desync: raw UDP fake (check path MTU): %w", err)
		}
	}

	return nil
}
func (u *UDPInjector) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.fd < 0 {
		return nil
	}
	err := unix.Close(u.fd)
	u.fd = -1
	return err
}
