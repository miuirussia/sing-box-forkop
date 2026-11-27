package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	mdns "github.com/miekg/dns"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

func TestDesyncProbeUsesExplicitDNS(t *testing.T) {
	globalCtx = include.Context(context.Background())
	var queries atomic.Int64
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &mdns.Server{PacketConn: socket, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
		queries.Add(1)
		response := new(mdns.Msg)
		response.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == mdns.TypeA {
			response.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: r.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.IPv4(127, 0, 0, 1)}}
		}
		_ = w.WriteMsg(response)
	})}
	go func() { _ = server.ActivateAndServe() }()
	defer server.Shutdown()
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("resolved directly")) }))
	defer httpServer.Close()
	_, port, _ := net.SplitHostPort(httpServer.Listener.Addr().String())
	cmd := newDesyncCommand()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"probe", "--strategy", "mode=split split_pos=1", "--target", "http://probe.example:" + port, "--protocol", "http", "--dns-server", "udp://" + socket.LocalAddr().String(), "--timeout", "3s"})
	if err = cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var result desyncProbeResult
	if err = json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Success || queries.Load() == 0 {
		t.Fatalf("independent DNS failed: %+v queries=%d", result, queries.Load())
	}
}
func TestDesyncProbeDNSOptions(t *testing.T) {
	o := option.DesyncOptions{}
	o.BindInterface = "test-wan"
	o.RoutingMark = 128
	dns, err := desyncProbeDNS([]string{"https://dns.example/dns-query", "udp://9.9.9.9"}, o)
	if err != nil {
		t.Fatal(err)
	}
	first := dns.Servers[0]
	if first.Tag != "probe-dns-1" {
		t.Fatal("numeric bootstrap not created before dependent DNS")
	}
	remote := first.Options.(*option.RemoteDNSServerOptions)
	if remote.RoutingMark != 128 || remote.BindInterface != "test-wan" || remote.Detour != "" {
		t.Fatal("DNS lost direct marked interface options")
	}
	for _, uri := range []string{"local://", "fakeip://", "https://dns.example/dns-query", "udp://127.0.0.1:0", "udp://127.0.0.1/path"} {
		if _, err = desyncProbeDNS([]string{uri}, o); err == nil {
			t.Fatalf("accepted unsafe/invalid DNS URI %s", uri)
		}
	}
}
