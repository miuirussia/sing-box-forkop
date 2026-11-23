package urltest

import (
	"context"
	"errors"
	"strings"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/miekg/dns"
)

// UDPProbe measures a DNS round trip through an outbound's connected UDP path.
type UDPProbe struct {
	server M.Socksaddr
	domain string
}

func NewUDPProbe(server M.Socksaddr, domain string) (*UDPProbe, error) {
	if !server.IsIP() || server.Addr.IsUnspecified() {
		return nil, errors.New("server must be an IP address")
	}
	if server.Port == 0 {
		server.Port = 53
	}
	if _, valid := dns.IsDomainName(domain); !valid {
		return nil, errors.New("invalid DNS question name")
	}
	return &UDPProbe{server: server, domain: dns.Fqdn(domain)}, nil
}

func (p *UDPProbe) Check(ctx context.Context, detour N.Dialer, timeout time.Duration) (uint16, error) {
	ctx, cancel := context.WithTimeout(context.WithValue(ctx, contextKeyOutbound{}, detour), timeout)
	defer cancel()
	query := new(dns.Msg).SetQuestion(p.domain, dns.TypeA)
	payload, err := query.Pack()
	if err != nil {
		return 0, err
	}
	start := time.Now()
	conn, err := detour.DialContext(ctx, N.NetworkUDP, p.server)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if _, err = conn.Write(payload); err != nil {
		return 0, err
	}
	buffer := make([]byte, 4096)
	count, err := conn.Read(buffer)
	if err != nil {
		return 0, err
	}
	var reply dns.Msg
	if err = reply.Unpack(buffer[:count]); err != nil {
		return 0, err
	}
	if !reply.Response || reply.Id != query.Id || len(reply.Question) != 1 ||
		!strings.EqualFold(reply.Question[0].Name, query.Question[0].Name) ||
		reply.Question[0].Qtype != query.Question[0].Qtype || reply.Question[0].Qclass != query.Question[0].Qclass {
		return 0, errors.New("UDP probe response does not match DNS question")
	}
	return max(uint16(time.Since(start)/time.Millisecond), 1), nil
}
