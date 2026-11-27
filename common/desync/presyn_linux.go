package desync

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/common/tlsspoof"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	"golang.org/x/sys/unix"
)

func validatePreSYN(o option.DesyncOptions) error {
	if o.WScale < 0 || o.WScale > 14 {
		return fmt.Errorf("desync: wscale must be 0..14")
	}
	if o.WSize > 0 && o.WScale > 0 {
		return fmt.Errorf("desync: an exact small wsize and a positive wscale cannot share Linux TCP_WINDOW_CLAMP; use either parameter")
	}
	if o.SynData != "" {
		payload, err := base64.StdEncoding.Strict().DecodeString(o.SynData)
		if err != nil || len(payload) < 1 || len(payload) > 1200 {
			return fmt.Errorf("desync: syndata requires a base64 fake SYN payload of 1..1200 bytes")
		}
	}
	return nil
}

func preSYNControl(o option.DesyncOptions) (control.Func, error) {
	if err := validatePreSYN(o); err != nil {
		return nil, err
	}
	if o.SynData == "" && o.WScale == 0 && !o.WScaleExplicit && !o.AutoTTL {
		return nil, nil
	}
	return func(network, address string, conn syscall.RawConn) error {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil
		}
		dst, err := netip.ParseAddrPort(address)
		if err != nil {
			return fmt.Errorf("desync: pre-SYN destination: %w", err)
		}
		var operationErr error
		err = conn.Control(func(raw uintptr) {
			fd := int(raw)
			if o.WScale != 0 || o.WScaleExplicit {
				// Linux selects ilog2(min(max(space, rmem_max), clamp))-15.
				// Set the clamp and, only if needed, enough locked receive space.
				// No global sysctl or other connection is changed.
				clamp := 65535 << o.WScale
				operationErr = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP, clamp)
				if operationErr != nil {
					return
				}
				if o.WScale > 0 {
					// tcp_full_space accounts for skb overhead; requesting only
					// the power-of-two threshold can negotiate one scale lower.
					target := clamp
					buffer, e := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
					if e != nil {
						operationErr = e
						return
					}
					if buffer < target {
						cookie, cookieErr := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
						if cookieErr != nil {
							operationErr = cookieErr
							return
						}
						if operationErr = rememberScaleBuffer(cookie, buffer, fd); operationErr != nil {
							return
						}
						operationErr = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, target)
						if operationErr == nil {
							buffer, operationErr = unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
						}
						if operationErr == nil && buffer < target {
							operationErr = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, target)
						}
						if operationErr != nil {
							operationErr = fmt.Errorf("desync: wscale=%d needs more receive space (CAP_NET_ADMIN for SO_RCVBUFFORCE): %w", o.WScale, operationErr)
							return
						}
					}
				}
			}
			if o.AutoTTL {
				operationErr = observeSYNACK(fd, dst)
				if operationErr != nil {
					return
				}
			}
			if o.SynData != "" {
				var source netip.Addr
				if dst.Addr().Is4() && o.Inet4BindAddress != nil {
					source = o.Inet4BindAddress.Build(netip.IPv4Unspecified())
				} else if dst.Addr().Is6() && o.Inet6BindAddress != nil {
					source = o.Inet6BindAddress.Build(netip.IPv6Unspecified())
				}
				payload, _ := base64.StdEncoding.Strict().DecodeString(o.SynData)
				operationErr = tlsspoof.InjectSYNPayload(fd, dst, source, payload, o.TTL)
			}
		})
		return errors.Join(err, operationErr)
	}, nil
}

type initialScaleBuffer struct {
	size   int
	socket int
}

var initialScaleBuffers = struct {
	sync.Mutex
	entries map[uint64]initialScaleBuffer
}{entries: make(map[uint64]initialScaleBuffer)}

func rememberScaleBuffer(cookie uint64, size, socket int) error {
	initialScaleBuffers.Lock()
	defer initialScaleBuffers.Unlock()
	if len(initialScaleBuffers.entries) >= 4096 {
		// Failed dials never reach NewConn. Reap only closed/reused sockets;
		// an arbitrary TTL could discard the restoration state of a live,
		// legitimately slow connect(). Socket cookies prevent fd-reuse races.
		for key, value := range initialScaleBuffers.entries {
			actual, err := unix.GetsockoptUint64(value.socket, unix.SOL_SOCKET, unix.SO_COOKIE)
			if err != nil || actual != key {
				delete(initialScaleBuffers.entries, key)
			}
		}
	}
	if len(initialScaleBuffers.entries) >= 4096 {
		return fmt.Errorf("desync: too many pending SYN window configurations")
	}
	initialScaleBuffers.entries[cookie] = initialScaleBuffer{size, socket}
	return nil
}

// Window scaling is fixed by the handshake, so the temporary receive-buffer
// increase can be undone before any ClientHello/application bytes are sent.
// In particular, a large advertised scale must not leave a router with a 2GiB
// receive queue for the lifetime of every connection.
func restoreScaleBuffer(conn net.Conn) error {
	sc, ok := common.Cast[syscall.Conn](conn)
	if !ok {
		return nil
	}
	return control.Conn(sc, func(raw uintptr) error {
		fd := int(raw)
		cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
		if err != nil {
			return err
		}
		initialScaleBuffers.Lock()
		original, found := initialScaleBuffers.entries[cookie]
		delete(initialScaleBuffers.entries, cookie)
		initialScaleBuffers.Unlock()
		if !found {
			return nil
		}
		// Linux returns twice the requested SO_RCVBUF value.
		if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, original.size/2); err != nil {
			return fmt.Errorf("desync: restore initial receive buffer: %w", err)
		}
		return nil
	})
}

var synObservations = struct {
	sync.Mutex
	entries map[string]ttlObservation
	active  map[string]chan struct{}
}{entries: make(map[string]ttlObservation), active: make(map[string]chan struct{})}

func observationKey(cookie uint64, remote, local string) string {
	return fmt.Sprintf("%d|%s|%s", cookie, remote, local)
}

// A short-lived raw receiver observes only SYN-ACK metadata. There is at most one
// receiver per destination/netns, and at most 64 receivers in the entire process.
// Its descriptor and goroutine expire after three seconds even if connect fails.
func observeSYNACK(tcpSocket int, dst netip.AddrPort) error {
	cookie, err := unix.GetsockoptUint64(tcpSocket, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	if err != nil {
		return fmt.Errorf("desync: autottl needs Linux SO_NETNS_COOKIE: %w", err)
	}
	key := observationKey(cookie, dst.String(), "")
	synObservations.Lock()
	if synObservations.active[key] != nil || len(synObservations.active) >= 64 {
		synObservations.Unlock()
		return nil // The documented fixed-TTL fallback covers a busy observer.
	}
	done := make(chan struct{})
	synObservations.active[key] = done
	synObservations.Unlock()
	finish := func() {
		synObservations.Lock()
		delete(synObservations.active, key)
		close(done)
		synObservations.Unlock()
	}
	family := unix.AF_INET
	if dst.Addr().Is6() {
		family = unix.AF_INET6
	}
	fd, err := unix.Socket(family, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		finish()
		return fmt.Errorf("desync: autottl observation requires CAP_NET_RAW: %w", err)
	}
	if family == unix.AF_INET6 {
		if err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVHOPLIMIT, 1); err == nil {
			err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
		}
		if err != nil {
			unix.Close(fd)
			finish()
			return err
		}
	}
	go func() {
		defer finish()
		defer unix.Close(fd)
		buffer, ancillary := make([]byte, 65536), make([]byte, 128)
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			if _, err := unix.Poll(poll, 100); err != nil && err != unix.EINTR {
				return
			}
			n, oobn, _, from, err := unix.Recvmsg(fd, buffer, ancillary, 0)
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			if err != nil {
				return
			}
			var remote, local netip.Addr
			var ttl int
			tcp := buffer[:n]
			if family == unix.AF_INET {
				if n < 40 || buffer[0]>>4 != 4 {
					continue
				}
				ihl := int(buffer[0]&15) * 4
				if ihl < 20 || n < ihl+20 {
					continue
				}
				remote = netip.AddrFrom4([4]byte(buffer[12:16]))
				local = netip.AddrFrom4([4]byte(buffer[16:20]))
				ttl, tcp = int(buffer[8]), buffer[ihl:n]
			} else {
				address, ok := from.(*unix.SockaddrInet6)
				if !ok || n < 20 {
					continue
				}
				remote = netip.AddrFrom16(address.Addr)
				messages, _ := unix.ParseSocketControlMessage(ancillary[:oobn])
				for _, message := range messages {
					if message.Header.Level != unix.IPPROTO_IPV6 {
						continue
					}
					if message.Header.Type == unix.IPV6_HOPLIMIT && len(message.Data) >= 4 {
						ttl = int(binary.NativeEndian.Uint32(message.Data))
					}
					if message.Header.Type == unix.IPV6_PKTINFO && len(message.Data) >= 16 {
						local = netip.AddrFrom16([16]byte(message.Data[:16]))
					}
				}
			}
			if remote != dst.Addr().Unmap() || !local.IsValid() || ttl == 0 || tcp[13]&0x12 != 0x12 || binary.BigEndian.Uint16(tcp) != dst.Port() {
				continue
			}
			initial := 64
			if ttl > 64 {
				initial = 128
			}
			if ttl > 128 {
				initial = 255
			}
			estimate := max(1, min(32, initial-ttl-1))
			localEndpoint := netip.AddrPortFrom(local, binary.BigEndian.Uint16(tcp[2:]))
			synObservations.Lock()
			now := time.Now()
			if len(synObservations.entries) >= 4096 {
				for k, entry := range synObservations.entries {
					if now.After(entry.expires) {
						delete(synObservations.entries, k)
					}
				}
				if len(synObservations.entries) >= 4096 {
					for k := range synObservations.entries {
						delete(synObservations.entries, k)
						break
					}
				}
			}
			synObservations.entries[observationKey(cookie, dst.String(), localEndpoint.String())] = ttlObservation{estimate, now.Add(10 * time.Minute)}
			synObservations.Unlock()
			// Keep observing for the bounded period: simultaneous connections to
			// this same destination have separate local ports.
		}
	}()
	return nil
}

func observedConnectionTTL(conn net.Conn) (int, bool) {
	sc, ok := common.Cast[syscall.Conn](conn)
	if !ok {
		return 0, false
	}
	var cookie uint64
	err := control.Conn(sc, func(fd uintptr) error {
		var err error
		cookie, err = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
		return err
	})
	if err != nil {
		return 0, false
	}
	key := observationKey(cookie, conn.RemoteAddr().String(), conn.LocalAddr().String())
	// The recv goroutine can be scheduled immediately after connect completes.
	// Bound this optional metadata wait; application I/O never waits for a probe.
	for attempt := 0; attempt < 5; attempt++ {
		synObservations.Lock()
		entry, ok := synObservations.entries[key]
		synObservations.Unlock()
		if ok && time.Now().Before(entry.expires) {
			return entry.ttl, true
		}
		if attempt != 4 {
			time.Sleep(time.Millisecond)
		}
	}
	return 0, false
}
