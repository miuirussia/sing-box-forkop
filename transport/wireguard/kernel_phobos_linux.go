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
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device"
	"github.com/vishvananda/netns"

	"golang.org/x/sys/unix"
)

type kernelPhobosRelay struct {
	endpoint      *Endpoint
	bind          conn.Bind
	detour        *ClientBind
	receive       []conn.ReceiveFunc
	peers         map[string]*kernelPhobosPeer
	workers       sync.WaitGroup
	listenPort    uint16
	kernelAddress netip.AddrPort
}

type kernelPhobosPeer struct {
	local            *net.UDPConn
	remote           conn.Endpoint
	handshakePending atomic.Bool
}

func newKernelPhobosRelay(endpoint *Endpoint) (_ *kernelPhobosRelay, _ []peerConfig, _ netlink.Link, err error) {
	if endpoint.options.Phobos == nil || len(endpoint.peers) == 0 {
		return nil, nil, nil, fmt.Errorf("%w: Phobos relay requires obfuscation and at least one peer", errKernelUnavailable)
	}
	bind, connectDomain := endpoint.createBind()
	relay := &kernelPhobosRelay{
		endpoint: endpoint,
		bind:     bind,
		peers:    make(map[string]*kernelPhobosPeer),
	}
	if detour, ok := common.Cast[*ClientBind](bind); ok && detour.isConnect {
		relay.detour = detour
	}
	defer func() {
		if err != nil {
			if closeErr := relay.Close(); closeErr != nil {
				err = fmt.Errorf("clean up Phobos relay after %v: %w", err, closeErr)
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
	paths := make([]*kernelPhobosPeer, len(peers))
	for i, peer := range peers {
		var remote string
		switch {
		case peer.endpoint.IsValid():
			remote = netip.AddrPortFrom(peer.endpoint.Addr().Unmap(), peer.endpoint.Port()).String()
		case connectDomain:
			remote = peer.destination.String()
		default:
			return nil, nil, nil, fmt.Errorf("%w: Phobos peer %d has no endpoint address", errKernelUnavailable, i)
		}
		path := relay.peers[remote]
		if path == nil {
			remoteEndpoint, err := bind.ParseEndpoint(remote)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("parse Phobos peer %d: %w", i, err)
			}
			path = &kernelPhobosPeer{remote: remoteEndpoint}
			relay.peers[remote] = path
		}
		paths[i] = path
	}
	relay.receive, relay.listenPort, err = bind.Open(endpoint.options.ListenPort)
	if err != nil {
		return nil, nil, nil, kernelSetupError("open Phobos outer UDP bind", err)
	}
	link, err := createKernelLink(endpoint.options.Name, C.TypeWireGuard, endpoint.options.MTU, relay.addKernelLink)
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

func (r *kernelPhobosRelay) addKernelLink(link netlink.Link) error {
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

func (r *kernelPhobosRelay) addKernelLinkInNamespace(link netlink.Link, outerNamespace netns.NsHandle) error {
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("%w: create private Phobos network namespace: %w", errKernelUnavailable, err)
	}
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("find Phobos loopback interface: %w", err)
	}
	if err = netlink.LinkSetUp(loopback); err != nil {
		return fmt.Errorf("bring up Phobos loopback interface: %w", err)
	}
	for _, peer := range r.peers {
		peer.local, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return fmt.Errorf("listen on Phobos loopback socket: %w", err)
		}
	}
	// WireGuard keeps its UDP sockets in the namespace where its link was
	// created. The relay's loopback sockets keep that namespace alive.
	if err = netlink.LinkAdd(link); err != nil {
		return err
	}
	if err = netlink.LinkSetNsFd(link, int(outerNamespace)); err != nil {
		return fmt.Errorf("move Phobos interface to the outer network namespace: %w", err)
	}
	link.Attrs().Index = 0
	return nil
}

func (r *kernelPhobosRelay) start(port uint16) {
	r.kernelAddress = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port)
	r.run()
}

func (r *kernelPhobosRelay) run() {
	for _, peer := range r.peers {
		r.workers.Go(func() {
			packet := make([]byte, 65535)
			for {
				size, source, err := peer.local.ReadFromUDPAddrPort(packet)
				if err != nil {
					if !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrDeadlineExceeded) {
						r.endpoint.options.Logger.Debug("read Phobos loopback UDP: ", err)
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
				}
				err = r.bind.Send([][]byte{packet[:size]}, peer.remote, 0)
				if err != nil && !errors.Is(err, net.ErrClosed) {
					r.endpoint.options.Logger.Debug("send Phobos UDP: ", err)
				}
			}
		})
	}
	for _, receive := range r.receive {
		r.workers.Go(func() { r.receivePackets(receive, r.kernelAddress) })
	}
}

func (r *kernelPhobosRelay) rebind() error {
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

func (r *kernelPhobosRelay) receivePackets(receive conn.ReceiveFunc, kernelAddress netip.AddrPort) {
	batchSize := r.bind.BatchSize()
	packets := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	sources := make([]conn.Endpoint, batchSize)
	for i := range packets {
		packets[i] = make([]byte, 65535)
	}
	for {
		count, err := receive(packets, sizes, sources)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				r.endpoint.options.Logger.Debug("receive Phobos UDP: ", err)
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
			_, err = peer.local.WriteToUDPAddrPort(packets[i][:sizes[i]], kernelAddress)
			if err != nil && !errors.Is(err, net.ErrClosed) {
				r.endpoint.options.Logger.Debug("write Phobos loopback UDP: ", err)
			}
		}
	}
}

func (r *kernelPhobosRelay) Close() error {
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
