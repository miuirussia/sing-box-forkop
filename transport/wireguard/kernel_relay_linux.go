//go:build linux && !android

package wireguard

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device"
	"github.com/vishvananda/netns"

	"golang.org/x/sys/unix"
)

type kernelUDPRelay struct {
	endpoint      *Endpoint
	bind          conn.Bind
	detour        *ClientBind
	receive       []conn.ReceiveFunc
	peers         map[string]*kernelRelayPeer
	workers       sync.WaitGroup
	listenPort    uint16
	kernelAddress netip.AddrPort
}

type kernelRelayPeer struct {
	local            *net.UDPConn
	remote           conn.Endpoint
	handshakePending atomic.Bool
}

func newKernelUDPRelay(endpoint *Endpoint, linkKind string) (_ *kernelUDPRelay, _ []peerConfig, _ netlink.Link, err error) {
	if len(endpoint.peers) == 0 {
		return nil, nil, nil, fmt.Errorf("%w: kernel UDP relay requires at least one peer", errKernelUnavailable)
	}
	bind, connectDomain := endpoint.createBind()
	if standardBind, ok := bind.(*conn.StdNetBind); ok {
		standardBind.EnableAdaptiveReceiveBuffers()
	}
	relay := &kernelUDPRelay{
		endpoint: endpoint,
		bind:     bind,
		peers:    make(map[string]*kernelRelayPeer),
	}
	if detour, ok := common.Cast[*ClientBind](bind); ok && detour.isConnect {
		relay.detour = detour
	}
	defer func() {
		if err != nil {
			if closeErr := relay.Close(); closeErr != nil {
				err = fmt.Errorf("clean up kernel UDP relay after %w: %w", err, closeErr)
			}
		}
	}()
	var peers []peerConfig
	if connectDomain {
		peers = append([]peerConfig(nil), endpoint.peers...)
	} else {
		peers, err = resolveKernelPeers(endpoint)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	paths := make([]*kernelRelayPeer, len(peers))
	for i, peer := range peers {
		var remote string
		switch {
		case peer.endpoint.IsValid():
			remote = netip.AddrPortFrom(peer.endpoint.Addr().Unmap(), peer.endpoint.Port()).String()
		case connectDomain:
			remote = peer.destination.String()
		default:
			return nil, nil, nil, fmt.Errorf("%w: relay peer %d has no endpoint address", errKernelUnavailable, i)
		}
		path := relay.peers[remote]
		if path == nil {
			remoteEndpoint, err := bind.ParseEndpoint(remote)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("parse relay peer %d: %w", i, err)
			}
			path = &kernelRelayPeer{remote: remoteEndpoint}
			relay.peers[remote] = path
		}
		paths[i] = path
	}
	relay.receive, relay.listenPort, err = bind.Open(endpoint.options.ListenPort)
	if err != nil {
		return nil, nil, nil, kernelSetupError("open relay outer UDP bind", err)
	}
	link, err := createKernelLink(endpoint.options.Name, linkKind, endpoint.options.MTU, relay.addKernelLink)
	if err != nil {
		return nil, nil, nil, err
	}
	// Each outer address has a stable loopback endpoint. WireGuard demultiplexes
	// peers sharing an address by their public keys.
	for i, path := range paths {
		peers[i].endpoint = path.local.LocalAddr().(*net.UDPAddr).AddrPort()
	}
	return relay, peers, link, nil
}

func (r *kernelUDPRelay) addKernelLink(link netlink.Link) error {
	outerNamespace, err := netns.Get()
	if err != nil {
		return fmt.Errorf("open current network namespace: %w", err)
	}
	defer outerNamespace.Close()
	result := make(chan error)
	setup := func() {
		result <- r.addKernelLinkInNamespace(link, outerNamespace)
	}
	go func() {
		runtime.LockOSThread()
		if unix.Gettid() == os.Getpid() {
			// The runtime cannot discard the main thread. Keep it occupied
			// until another thread has been locked for the namespace setup.
			defer runtime.UnlockOSThread()
			workerReady := make(chan struct{})
			go func() {
				runtime.LockOSThread()
				close(workerReady)
				setup()
			}()
			<-workerReady
			return
		}
		setup()
	}()
	return <-result
}

func (r *kernelUDPRelay) addKernelLinkInNamespace(link netlink.Link, outerNamespace netns.NsHandle) error {
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("%w: create private relay network namespace: %w", errKernelUnavailable, err)
	}
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("find relay loopback interface: %w", err)
	}
	if err = netlink.LinkSetUp(loopback); err != nil {
		return fmt.Errorf("bring up relay loopback interface: %w", err)
	}
	for _, peer := range r.peers {
		peer.local, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return fmt.Errorf("listen on relay loopback socket: %w", err)
		}
	}
	// WireGuard keeps its UDP sockets in the namespace where its link was
	// created. The relay's loopback sockets keep that namespace alive.
	if err = netlink.LinkAdd(link); err != nil {
		return err
	}
	if err = netlink.LinkSetNsFd(link, int(outerNamespace)); err != nil {
		return fmt.Errorf("move kernel interface to the outer network namespace: %w", err)
	}
	link.Attrs().Index = 0
	return nil
}

func (r *kernelUDPRelay) start(port uint16) {
	r.kernelAddress = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port)
	r.run()
}

func (r *kernelUDPRelay) run() {
	amnezia := r.endpoint.options.Amnezia
	sendsHandshakeDecoys := amnezia != nil && (amnezia.JC > 0 ||
		amnezia.I1 != "" || amnezia.I2 != "" || amnezia.I3 != "" || amnezia.I4 != "" || amnezia.I5 != "")
	for _, peer := range r.peers {
		r.workers.Go(func() {
			packet := make([]byte, 65535)
			for {
				size, source, err := peer.local.ReadFromUDPAddrPort(packet)
				if err != nil {
					if !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrDeadlineExceeded) {
						r.endpoint.options.Logger.Debug("read relay loopback UDP: ", err)
					}
					return
				}
				if source != r.kernelAddress {
					continue
				}
				if r.detour != nil && size == device.MessageInitiationSize &&
					binary.LittleEndian.Uint32(packet) == device.MessageInitiationType && peer.handshakePending.Swap(true) {
					// The kernel only knows the loopback endpoint and cannot reset the outer session.
					r.detour.clearPath()
					if sendsHandshakeDecoys {
						// The kernel already sent this initiation's decoys on the old session.
						// Let the next attempt send its decoys on the replacement session.
						peer.handshakePending.Store(false)
						continue
					}
				}
				err = r.bind.Send([][]byte{packet[:size]}, peer.remote, 0)
				if err != nil && !errors.Is(err, net.ErrClosed) {
					r.endpoint.options.Logger.Debug("send relay UDP: ", err)
				}
			}
		})
	}
	for _, receive := range r.receive {
		r.workers.Go(func() { r.receivePackets(receive) })
	}
}

func (r *kernelUDPRelay) rebind() error {
	// Keep the loopback sockets and their ports, which are configured as
	// endpoints on the kernel device. Only reopen the outer UDP bind.
	var errs []error
	for _, peer := range r.peers {
		errs = append(errs, peer.local.SetReadDeadline(time.Now()))
	}
	errs = append(errs, r.bind.Close())
	r.workers.Wait()
	if err := errors.Join(errs...); err != nil {
		return err
	}
	for _, peer := range r.peers {
		if err := peer.local.SetReadDeadline(time.Time{}); err != nil {
			return err
		}
		peer.handshakePending.Store(false)
	}
	receive, port, err := r.bind.Open(r.listenPort)
	if err != nil {
		return err
	}
	r.receive = receive
	r.listenPort = port
	r.run()
	return nil
}

func (r *kernelUDPRelay) receivePackets(receive conn.ReceiveFunc) {
	batchSize := r.bind.BatchSize()
	packets := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	sources := make([]conn.Endpoint, batchSize)
	if _, isStandardBind := r.bind.(*conn.StdNetBind); !isStandardBind {
		for i := range packets {
			packets[i] = make([]byte, 65535)
		}
	}
	for {
		count, err := receive(packets, sizes, sources)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				r.endpoint.options.Logger.Debug("receive relay UDP: ", err)
			}
			return
		}
		for i := range count {
			if sizes[i] == 0 || sources[i] == nil {
				continue
			}
			peer := r.peers[sources[i].DstToString()]
			if peer == nil {
				continue
			}
			if r.detour != nil {
				peer.handshakePending.Store(false)
			}
			_, err = peer.local.WriteToUDPAddrPort(packets[i][:sizes[i]], r.kernelAddress)
			if err != nil && !errors.Is(err, net.ErrClosed) {
				r.endpoint.options.Logger.Debug("write relay loopback UDP: ", err)
			}
		}
	}
}

func (r *kernelUDPRelay) Close() error {
	var errs []error
	for _, peer := range r.peers {
		if peer.local != nil {
			errs = append(errs, peer.local.Close())
		}
	}
	r.endpoint.closeEgressPool()
	errs = append(errs, r.bind.Close())
	r.workers.Wait()
	return errors.Join(errs...)
}
