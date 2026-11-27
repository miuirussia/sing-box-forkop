//go:build linux || darwin || (windows && (amd64 || 386))

package tlsspoof

import (
	"encoding/binary"
	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"net/netip"
	"testing"
)

func TestBadChecksumCannotBecomeEquivalentZero(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.1:1234")
	dst := netip.MustParseAddrPort("192.0.2.2:443")
	payload := []byte{0, 0}
	frame := buildTCPSegment(src, dst, spoofPacketInfo{seqNum: 1, ackNum: 1}, payload)
	valid := header.TCP(frame[20:]).Checksum()
	binary.BigEndian.PutUint16(payload, valid)
	frame = buildTCPSegment(src, dst, spoofPacketInfo{seqNum: 1, ackNum: 1}, payload)
	if got := header.TCP(frame[20:]).Checksum(); got != 0 && got != 0xffff {
		t.Fatalf("failed to construct zero checksum: %x", got)
	}
	frame = buildTCPSegment(src, dst, spoofPacketInfo{seqNum: 1, ackNum: 1, corrupt: true}, payload)
	pseudo := header.PseudoHeaderChecksum(header.TCPProtocolNumber, src.Addr().AsSlice(), dst.Addr().AsSlice(), uint16(len(frame)-20))
	if checksum.Checksum(frame[20:], pseudo) == 0xffff {
		t.Fatal("corrupted checksum still validates")
	}
}
