package main

import (
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// Probe DNS never passes through the active instance or system FakeIP resolver.
func desyncProbeDNS(uris []string, o option.DesyncOptions) (*option.DNSOptions, error) {
	if len(uris) == 0 {
		uris = []string{"udp://1.1.1.1"}
	}
	if len(uris) > 8 {
		return nil, fmt.Errorf("at most 8 probe DNS servers")
	}
	parsed := make([]*url.URL, len(uris))
	bootstrap := ""
	numericTags := map[string]bool{}
	for i, input := range uris {
		if !strings.Contains(input, "://") {
			if ip, err := netip.ParseAddr(input); err == nil {
				input = "udp://" + ip.String()
				if ip.Is6() {
					input = "udp://[" + ip.String() + "]"
				}
			} else {
				input = "udp://" + input
			}
		}
		u, err := url.Parse(input)
		if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
			return nil, fmt.Errorf("invalid probe DNS URI %q", input)
		}
		switch u.Scheme {
		case "udp", "tcp", "tls", "https", "quic", "h3":
		default:
			return nil, fmt.Errorf("unsupported probe DNS scheme %q", u.Scheme)
		}
		if u.Scheme != "https" && u.Scheme != "h3" && u.Path != "" && u.Path != "/" {
			return nil, fmt.Errorf("DNS URI path requires HTTPS")
		}
		if _, err = netip.ParseAddr(u.Hostname()); err == nil && bootstrap == "" {
			bootstrap = fmt.Sprintf("probe-dns-%d", i)
		}
		if _, err = netip.ParseAddr(u.Hostname()); err == nil {
			numericTags[fmt.Sprintf("probe-dns-%d", i)] = true
		}
		parsed[i] = u
	}
	var servers []option.DNSServerOptions
	var tags []string
	for i, u := range parsed {
		port := uint64(53)
		switch u.Scheme {
		case "tls", "quic":
			port = 853
		case "https", "h3":
			port = 443
		}
		if u.Port() != "" {
			var err error
			port, err = strconv.ParseUint(u.Port(), 10, 16)
			if err != nil || port == 0 {
				return nil, fmt.Errorf("invalid DNS port")
			}
		}
		d := option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{RoutingMark: o.RoutingMark, BindInterface: o.BindInterface, Inet4BindAddress: o.Inet4BindAddress, Inet6BindAddress: o.Inet6BindAddress, NetNs: o.NetNs, ConnectTimeout: badoption.Duration(3 * time.Second)}}
		if _, err := netip.ParseAddr(u.Hostname()); err != nil {
			if bootstrap == "" {
				return nil, fmt.Errorf("named probe DNS endpoint requires a numeric --dns-server bootstrap")
			}
			d.DomainResolver = &option.DomainResolveOptions{Server: bootstrap}
		}
		remote := option.RemoteDNSServerOptions{RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{DialerOptions: d}, DNSServerAddressOptions: option.DNSServerAddressOptions{Server: u.Hostname(), ServerPort: uint16(port)}}
		tag := fmt.Sprintf("probe-dns-%d", i)
		server := option.DNSServerOptions{Type: u.Scheme, Tag: tag}
		switch u.Scheme {
		case "udp", "tcp":
			server.Options = &remote
		case "tls", "quic":
			server.Options = &option.RemoteTLSDNSServerOptions{RemoteDNSServerOptions: remote, OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true, ServerName: u.Hostname()}}}
		case "https", "h3":
			path := u.EscapedPath()
			if path == "" {
				path = "/dns-query"
			}
			server.Options = &option.RemoteHTTPSDNSServerOptions{RemoteTLSDNSServerOptions: option.RemoteTLSDNSServerOptions{RemoteDNSServerOptions: remote, OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true, ServerName: u.Hostname()}}}, Path: path}
		}
		servers = append(servers, server)
		tags = append(tags, tag)
	}
	sort.SliceStable(servers, func(i, j int) bool { return numericTags[servers[i].Tag] && !numericTags[servers[j].Tag] })
	servers = append(servers, option.DNSServerOptions{Type: C.DNSTypeFallback, Tag: "probe-dns", Options: &option.FallbackDNSServerOptions{Servers: tags, Strategy: "sequential", Timeout: badoption.Duration(2 * time.Second)}})
	return &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{Servers: servers, Final: "probe-dns"}}, nil
}
