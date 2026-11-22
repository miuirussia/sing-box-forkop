//go:build linux && !android

package wireguard

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/wireguard-go/conn"
)

type kernelPhobosRelay struct {
	endpoint      *Endpoint
	bind          conn.Bind
	receive       []conn.ReceiveFunc
	peers         map[string]*kernelPhobosPeer
	workers       sync.WaitGroup
	listenPort    uint16
	kernelAddress netip.AddrPort
}

type kernelPhobosPeer struct {
	local  *net.UDPConn
	remote conn.Endpoint
}

func newKernelPhobosRelay(endpoint *Endpoint) (_ *kernelPhobosRelay, _ []peerConfig, err error) {
	if endpoint.options.Phobos == nil || len(endpoint.peers) == 0 {
		return nil, nil, fmt.Errorf("%w: Phobos relay requires obfuscation and at least one peer", errKernelUnavailable)
	}
	bind, connectDomain := endpoint.createBind()
	relay := &kernelPhobosRelay{
		endpoint: endpoint,
		bind:     bind,
		peers:    make(map[string]*kernelPhobosPeer),
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
			return nil, nil, err
		}
	}
	for i, peer := range peers {
		var remote string
		switch {
		case peer.endpoint.IsValid():
			remote = netip.AddrPortFrom(peer.endpoint.Addr().Unmap(), peer.endpoint.Port()).String()
		case connectDomain:
			remote = peer.destination.String()
		default:
			return nil, nil, fmt.Errorf("%w: Phobos peer %d has no endpoint address", errKernelUnavailable, i)
		}
		path := relay.peers[remote]
		if path == nil {
			remoteEndpoint, err := bind.ParseEndpoint(remote)
			if err != nil {
				return nil, nil, fmt.Errorf("parse Phobos peer %d: %w", i, err)
			}
			local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				return nil, nil, kernelSetupError("listen on Phobos loopback socket", err)
			}
			path = &kernelPhobosPeer{local: local, remote: remoteEndpoint}
			relay.peers[remote] = path
		}
		// Each outer address has a stable loopback endpoint. WireGuard demultiplexes
		// peers sharing an address by their public keys.
		peers[i].endpoint = path.local.LocalAddr().(*net.UDPAddr).AddrPort()
	}
	relay.receive, relay.listenPort, err = bind.Open(endpoint.options.ListenPort)
	if err != nil {
		return nil, nil, kernelSetupError("open Phobos outer UDP bind", err)
	}
	return relay, peers, nil
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
		errs = append(errs, peer.local.Close())
	}
	r.endpoint.closeEgressPool()
	errs = append(errs, r.bind.Close())
	r.workers.Wait()
	return errors.Join(errs...)
}
