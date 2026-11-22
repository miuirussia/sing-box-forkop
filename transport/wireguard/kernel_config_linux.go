//go:build linux && !android

package wireguard

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/sagernet/netlink"
	"github.com/sagernet/netlink/nl"
	"github.com/sagernet/sing-box/option"

	"golang.org/x/sys/unix"
)

// Attribute IDs from the WireGuard and AmneziaWG netlink UAPI headers.
const (
	kernelGetDevice    = 0
	kernelSetDevice    = 1
	kernelIfindex      = 1
	kernelPrivateKey   = 3
	kernelListenPort   = 6
	kernelFwmark       = 7
	kernelPeers        = 8
	kernelJc           = 9
	kernelJmin         = 10
	kernelJmax         = 11
	kernelS1           = 12
	kernelS2           = 13
	kernelH1           = 14
	kernelS3           = 19
	kernelS4           = 20
	kernelI1           = 21
	kernelHeaderKey    = 26
	kernelExtraPadding = 27
	kernelRekeyTime    = 28
	kernelRekeyTimeout = 29
	kernelRejectTime   = 30
	kernelKeepalive    = 31
	kernelMaxAttempts  = 32
	kernelTrailers     = 33
	kernelNoCookies    = 34

	kernelPeerKey        = 1
	kernelPeerPSK        = 2
	kernelPeerEndpoint   = 4
	kernelPeerKeepalive  = 5
	kernelPeerAllowedIPs = 9

	kernelAllowedIPFamily = 1
	kernelAllowedIPAddr   = 2
	kernelAllowedIPBits   = 3
)

type kernelConfig struct {
	family  *netlink.GenlFamily
	index   int
	amnezia bool
}

func (c kernelConfig) request(command uint8, flags int) *nl.NetlinkRequest {
	req := nl.NewNetlinkRequest(int(c.family.ID), flags)
	req.AddData(&nl.Genlmsg{Command: command, Version: uint8(c.family.Version)})
	req.AddData(nl.NewRtAttr(kernelIfindex, nl.Uint32Attr(uint32(c.index))))
	return req
}

func (c kernelConfig) apply(endpoint *Endpoint, mark uint32, listenPort uint16, peers []peerConfig) error {
	version := c.family.Version
	if !c.amnezia && version != 1 || c.amnezia && (version < 1 || version > 3) {
		return fmt.Errorf("%w: unsupported %s netlink version %d", errKernelUnavailable, c.family.Name, version)
	}
	req := c.request(kernelSetDevice, unix.NLM_F_ACK)
	privateKey, err := base64.StdEncoding.DecodeString(endpoint.options.PrivateKey)
	if err != nil {
		return fmt.Errorf("decode WireGuard private key: %w", err)
	}
	req.AddData(nl.NewRtAttr(kernelPrivateKey, privateKey))
	if listenPort != 0 {
		req.AddData(nl.NewRtAttr(kernelListenPort, nl.Uint16Attr(listenPort)))
	}
	if mark != 0 {
		req.AddData(nl.NewRtAttr(kernelFwmark, nl.Uint32Attr(mark)))
	}
	if c.amnezia && endpoint.options.Amnezia != nil {
		attrs, err := c.amneziaAttributes(endpoint.options.Amnezia)
		if err != nil {
			return err
		}
		for _, attr := range attrs {
			req.AddData(attr)
		}
	}
	_, err = req.Execute(unix.NETLINK_GENERIC, 0)
	if err != nil {
		if c.amnezia && errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("%w: AmneziaWG module rejected the device parameters: %w", errKernelUnavailable, err)
		}
		return kernelSetupError("configure kernel WireGuard device", err)
	}
	for i, peer := range peers {
		err = c.setPeer(peer)
		if err != nil {
			return fmt.Errorf("configure kernel WireGuard peer %d: %w", i, err)
		}
	}
	return nil
}

func (c kernelConfig) setPeer(peer peerConfig) error {
	key, err := hex.DecodeString(peer.publicKeyHex)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	psk, err := hex.DecodeString(peer.preSharedKeyHex)
	if err != nil {
		return fmt.Errorf("decode preshared key: %w", err)
	}
	var keepalive []byte
	if peer.keepalive != nil {
		packed, err := packKernelRange16(peer.keepalive)
		if err != nil {
			return err
		}
		if c.amnezia && c.family.Version >= 3 {
			keepalive = nl.Uint32Attr(packed)
		} else if peer.keepalive.From == peer.keepalive.To {
			keepalive = nl.Uint16Attr(uint16(peer.keepalive.From))
		} else {
			return fmt.Errorf("%w: persistent keepalive range requires AmneziaWG netlink v3", errKernelUnavailable)
		}
	}
	var address []byte
	if peer.endpoint.IsValid() {
		address, err = kernelSockaddr(peer.endpoint)
		if err != nil {
			return err
		}
	}

	// Keep the nested netlink arrays below the message and attribute size limits.
	const prefixBatch = 128
	for start := 0; start < len(peer.allowedIPs); start += prefixBatch {
		req := c.request(kernelSetDevice, unix.NLM_F_ACK)
		peers := nl.NewRtAttr(kernelPeers|unix.NLA_F_NESTED, nil)
		entry := peers.AddRtAttr(unix.NLA_F_NESTED, nil)
		entry.AddRtAttr(kernelPeerKey, key)
		if start == 0 {
			if len(psk) > 0 {
				entry.AddRtAttr(kernelPeerPSK, psk)
			}
			if address != nil {
				entry.AddRtAttr(kernelPeerEndpoint, address)
			}
			if keepalive != nil {
				entry.AddRtAttr(kernelPeerKeepalive, keepalive)
			}
		}
		prefixes := entry.AddRtAttr(kernelPeerAllowedIPs|unix.NLA_F_NESTED, nil)
		for _, prefix := range peer.allowedIPs[start:min(start+prefixBatch, len(peer.allowedIPs))] {
			prefix = prefix.Masked()
			family := uint16(unix.AF_INET6)
			if prefix.Addr().Is4() {
				family = unix.AF_INET
			}
			allowed := prefixes.AddRtAttr(unix.NLA_F_NESTED, nil)
			allowed.AddRtAttr(kernelAllowedIPFamily, nl.Uint16Attr(family))
			allowed.AddRtAttr(kernelAllowedIPAddr, prefix.Addr().AsSlice())
			allowed.AddRtAttr(kernelAllowedIPBits, nl.Uint8Attr(uint8(prefix.Bits())))
		}
		req.AddData(peers)
		_, err = req.Execute(unix.NETLINK_GENERIC, 0)
		if err != nil {
			return kernelSetupError("set WireGuard peer", err)
		}
	}
	return nil
}

func (c kernelConfig) listenPort() (uint16, error) {
	msgs, err := c.request(kernelGetDevice, unix.NLM_F_DUMP).Execute(unix.NETLINK_GENERIC, c.family.ID)
	if err != nil {
		return 0, err
	}
	for _, msg := range msgs {
		if len(msg) < nl.SizeofGenlmsg {
			continue
		}
		attrs, err := nl.ParseRouteAttr(msg[nl.SizeofGenlmsg:])
		if err != nil {
			return 0, err
		}
		for _, attr := range attrs {
			if attr.Attr.Type == kernelListenPort && len(attr.Value) == 2 {
				port := binary.NativeEndian.Uint16(attr.Value)
				if port != 0 {
					return port, nil
				}
			}
		}
	}
	return 0, errors.New("kernel WireGuard listen port missing")
}

func resolveKernelPeers(endpoint *Endpoint) ([]peerConfig, error) {
	peers := append([]peerConfig(nil), endpoint.peers...)
	for i, peer := range peers {
		if !peer.destination.IsDomain() {
			continue
		}
		if endpoint.options.ResolvePeer == nil {
			return nil, fmt.Errorf("%w: no peer resolver", errKernelUnavailable)
		}
		addresses, err := endpoint.options.ResolvePeer(peer.destination.Fqdn)
		if err != nil {
			return nil, fmt.Errorf("%w: resolve peer %s: %w", errKernelUnavailable, peer.destination.Fqdn, err)
		}
		var address netip.Addr
		for _, candidate := range addresses {
			if !candidate.IsValid() {
				continue
			}
			candidate = candidate.Unmap()
			if address.IsValid() && address != candidate {
				return nil, fmt.Errorf("%w: peer %s resolves to multiple addresses", errKernelUnavailable, peer.destination.Fqdn)
			}
			address = candidate
		}
		if !address.IsValid() {
			return nil, fmt.Errorf("%w: no IP address for peer %s", errKernelUnavailable, peer.destination.Fqdn)
		}
		peers[i].endpoint = netip.AddrPortFrom(address, peer.destination.Port)
	}
	return peers, nil
}

func kernelSockaddr(endpoint netip.AddrPort) ([]byte, error) {
	addr := endpoint.Addr().Unmap()
	if addr.Is4() {
		buf := make([]byte, unix.SizeofSockaddrInet4)
		binary.NativeEndian.PutUint16(buf, unix.AF_INET)
		binary.BigEndian.PutUint16(buf[2:], endpoint.Port())
		copy(buf[4:], addr.AsSlice())
		return buf, nil
	}
	buf := make([]byte, unix.SizeofSockaddrInet6)
	binary.NativeEndian.PutUint16(buf, unix.AF_INET6)
	binary.BigEndian.PutUint16(buf[2:], endpoint.Port())
	copy(buf[8:], addr.AsSlice())
	if zone := addr.Zone(); zone != "" {
		index, err := strconv.ParseUint(zone, 10, 32)
		if err != nil {
			iface, err := net.InterfaceByName(zone)
			if err != nil {
				return nil, fmt.Errorf("find WireGuard endpoint zone: %w", err)
			}
			index = uint64(iface.Index)
		}
		binary.NativeEndian.PutUint32(buf[24:], uint32(index))
	}
	return buf, nil
}

func packKernelRange16(value *option.Range[uint32]) (uint32, error) {
	if value.From > value.To || value.To > math.MaxUint16 {
		return 0, fmt.Errorf("%w: value %s exceeds the kernel AmneziaWG range format", errKernelUnavailable, value)
	}
	return value.To<<16 | value.From, nil
}

func (c kernelConfig) amneziaAttributes(options *AmneziaOptions) ([]*nl.RtAttr, error) {
	var attrs []*nl.RtAttr
	for _, field := range []struct{ id, value int }{
		{kernelJc, options.JC}, {kernelJmin, options.JMin}, {kernelJmax, options.JMax},
		{kernelS1, options.S1}, {kernelS2, options.S2}, {kernelS3, options.S3}, {kernelS4, options.S4},
	} {
		if field.value > math.MaxUint16 {
			return nil, fmt.Errorf("%w: AmneziaWG attribute %d exceeds 16 bits", errKernelUnavailable, field.id)
		}
		if field.value > 0 {
			attrs = append(attrs, nl.NewRtAttr(field.id, nl.Uint16Attr(uint16(field.value))))
		}
	}
	for i, header := range []*option.Range[uint32]{options.H1, options.H2, options.H3, options.H4} {
		if header == nil {
			continue
		}
		var data []byte
		switch c.family.Version {
		case 1:
			if header.From != header.To {
				return nil, fmt.Errorf("%w: ranged headers require AmneziaWG netlink v2 or newer", errKernelUnavailable)
			}
			data = nl.Uint32Attr(header.From)
		case 2:
			data = nl.ZeroTerminated(header.String())
		case 3:
			data = nl.Uint64Attr(uint64(header.To)<<32 | uint64(header.From))
		}
		attrs = append(attrs, nl.NewRtAttr(kernelH1+i, data))
	}
	for i, packet := range []string{options.I1, options.I2, options.I3, options.I4, options.I5} {
		if packet == "" {
			continue
		}
		if strings.ContainsRune(packet, 0) || len(packet) > math.MaxUint16-5 {
			return nil, fmt.Errorf("%w: invalid kernel AmneziaWG signature packet I%d", errKernelUnavailable, i+1)
		}
		attrs = append(attrs, nl.NewRtAttr(kernelI1+i, nl.ZeroTerminated(packet)))
	}
	if options.HeaderProtectionKey != "" {
		key, err := base64.StdEncoding.DecodeString(options.HeaderProtectionKey)
		if err != nil {
			return nil, fmt.Errorf("decode AmneziaWG header protection key: %w", err)
		}
		attrs = append(attrs, nl.NewRtAttr(kernelHeaderKey, key))
	}
	for _, field := range []struct {
		id    int
		value *option.Range[uint32]
	}{
		{kernelExtraPadding, options.ContentPaddingAddition}, {kernelRekeyTime, options.RekeyAfterTime},
		{kernelRekeyTimeout, options.RekeyTimeout}, {kernelRejectTime, options.RejectAfterTime},
		{kernelKeepalive, options.KeepaliveTimeout}, {kernelMaxAttempts, options.MaxHandshakeAttempts},
	} {
		if field.value == nil {
			continue
		}
		value, err := packKernelRange16(field.value)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, nl.NewRtAttr(field.id, nl.Uint32Attr(value)))
	}
	if options.RandomTrailers {
		attrs = append(attrs, nl.NewRtAttr(kernelTrailers, nl.Uint8Attr(1)))
	}
	if options.DisableCookies {
		attrs = append(attrs, nl.NewRtAttr(kernelNoCookies, nl.Uint8Attr(1)))
	}
	for _, attr := range attrs {
		if c.family.Version < 3 && attr.Type >= kernelHeaderKey || uint32(attr.Type) > c.family.MaxAttr {
			return nil, fmt.Errorf("%w: AmneziaWG kernel module lacks attribute %d", errKernelUnavailable, attr.Type)
		}
	}
	return attrs, nil
}
