package desync

import (
	"net"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// domainPacketConn maps logical addresses outside the engine. Its immutable
// session mapping never performs DNS and preserves domains in both packet APIs.
type domainPacketConn struct {
	N.NetPacketConn
	actual, logical M.Socksaddr
}

func newDomainPacketConn(conn net.PacketConn, actual, logical M.Socksaddr) net.PacketConn {
	return &domainPacketConn{bufio.NewPacketConn(conn), actual, logical}
}
func (c *domainPacketConn) mapRead(addr M.Socksaddr) M.Socksaddr {
	if addr.Addr.IsValid() && addr.Addr.Unmap() == c.actual.Addr.Unmap() {
		return M.Socksaddr{Fqdn: c.logical.Fqdn, Port: addr.Port}
	}
	return addr
}
func (c *domainPacketConn) mapWrite(addr M.Socksaddr) M.Socksaddr {
	if addr.Fqdn == c.logical.Fqdn && !addr.Addr.IsValid() {
		return M.SocksaddrFrom(c.actual.Addr, addr.Port)
	}
	return addr
}
func (c *domainPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.NetPacketConn.ReadFrom(p)
	if addr != nil {
		addr = c.mapRead(M.SocksaddrFromNet(addr))
	}
	return n, addr, err
}
func (c *domainPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, net.InvalidAddrError("missing UDP destination")
	}
	destination := c.mapWrite(M.SocksaddrFromNet(addr))
	if !destination.IsIP() {
		return 0, net.InvalidAddrError("UDP destination is outside the resolved session")
	}
	return c.NetPacketConn.WriteTo(p, destination.UDPAddr())
}
func (c *domainPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	destination, err := c.NetPacketConn.ReadPacket(buffer)
	return c.mapRead(destination), err
}
func (c *domainPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	destination = c.mapWrite(destination)
	if !destination.IsIP() {
		buffer.Release()
		return net.InvalidAddrError("UDP destination is outside the resolved session")
	}
	return c.NetPacketConn.WritePacket(buffer, destination)
}
func (c *domainPacketConn) Upstream() any           { return c.NetPacketConn }
func (c *domainPacketConn) ReaderReplaceable() bool { return false }
func (c *domainPacketConn) WriterReplaceable() bool { return false }

var _ N.NetPacketConn = (*domainPacketConn)(nil)
