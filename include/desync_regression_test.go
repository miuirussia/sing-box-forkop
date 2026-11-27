//go:build integration

package include

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/desync"
	SJSON "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func regressionBox(t *testing.T, config string) *box.Box {
	t.Helper()
	ctx := Context(context.Background())
	var opts option.Options
	if err := SJSON.UnmarshalContext(ctx, []byte(config), &opts); err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Options: opts, Context: ctx})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	return instance
}

func TestDesyncResolvedAndSniffedHostsLearnSeparately(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer server.Close()
	actual := M.ParseSocksaddr(server.Listener.Addr().String())
	instance := regressionBox(t, `{"log":{"disabled":true},"outbounds":[{"type":"desync","tag":"dpi","preset":"auto","mode":"none"}]}`)
	out, _ := instance.Outbound().Outbound("dpi")
	for _, host := range []string{"alpha.shared.example.com", "beta.shared.example.com", "sniffed.example.net"} {
		t.Run(host, func(t *testing.T) {
			logical := M.Socksaddr{Fqdn: host, Port: actual.Port}
			metadata := adapter.InboundContext{Destination: logical, DestinationAddresses: []netip.Addr{actual.Addr}}
			if strings.HasPrefix(host, "sniffed") {
				metadata.Destination = actual
				metadata.Domain = host
			}
			ctx := adapter.WithContext(context.Background(), &metadata)
			// This is the production route helper used after Forkop's resolve action.
			conn, err := dialer.DialSerialNetwork(ctx, out, "tcp", metadata.Destination, metadata.DestinationAddresses, nil, nil, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			if _, err = io.ReadAll(conn); err != nil {
				t.Fatal(err)
			}
		})
	}
	stats := out.(interface{ DesyncStats() desync.Snapshot }).DesyncStats()
	for _, host := range []string{"alpha.shared.example.com", "beta.shared.example.com", "sniffed.example.net"} {
		found := false
		for key, entry := range stats.Entries {
			if strings.HasPrefix(key, "host:"+net.JoinHostPort(host, fmt.Sprint(actual.Port))+"|") {
				found = true
				if entry.Strategies["none"].Success != 1 {
					t.Fatalf("host statistics merged: %s %+v", key, entry)
				}
			}
		}
		if !found {
			t.Errorf("missing host identity %s: %+v", host, stats.Entries)
		}
	}
}

func TestDesyncProductionHalfClosePreservesResponse(t *testing.T) {
	for _, options := range []string{
		`"preset":"split"`,
		`"preset":"auto"`,
		`"preset":"auto","mode":"none"`,
	} {
		t.Run(options, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			request := []byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
			response := []byte("response generated only after EOF")
			result := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					result <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				data, err := io.ReadAll(conn)
				if err == nil && !bytes.Equal(data, request) {
					err = fmt.Errorf("request changed: %q", data)
				}
				if err == nil {
					_, err = conn.Write(response)
				}
				result <- err
			}()
			instance := regressionBox(t, `{"log":{"disabled":true},"outbounds":[{"type":"desync","tag":"dpi",`+options+`}]}`)
			out, _ := instance.Outbound().Outbound("dpi")
			conn, err := out.DialContext(context.Background(), "tcp", M.ParseSocksaddr(listener.Addr().String()))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err = conn.Write(request); err != nil {
				t.Fatal(err)
			}
			// These are the same unwrapping rules used by the production relay.
			if err = N.CloseWrite(conn); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(conn)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, response) {
				t.Fatalf("lost EOF response: %q", got)
			}
			if err = <-result; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDesyncProductionSOCKSCascadePreservesBinaryHandshake(t *testing.T) {
	for _, mode := range []string{"split", "tlsrec", "fake_split", "multi_disorder"} {
		t.Run(mode, func(t *testing.T) {
			server, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			result := make(chan error, 1)
			go func() {
				conn, err := server.Accept()
				if err != nil {
					result <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				greeting := make([]byte, 3)
				if _, err = io.ReadFull(conn, greeting); err == nil && !bytes.Equal(greeting, []byte{5, 1, 0}) {
					err = fmt.Errorf("wrong SOCKS greeting: %x", greeting)
				}
				if err == nil {
					_, err = conn.Write([]byte{5, 0})
				}
				request := make([]byte, 10)
				if err == nil {
					_, err = io.ReadFull(conn, request)
				}
				if err == nil && !bytes.Equal(request[:4], []byte{5, 1, 0, 1}) {
					err = fmt.Errorf("wrong SOCKS CONNECT: %x", request)
				}
				if err == nil {
					_, err = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
				}
				var payload []byte
				if err == nil {
					payload, err = io.ReadAll(conn)
				}
				if err == nil && string(payload) != "application once" {
					err = fmt.Errorf("payload changed/repeated: %q", payload)
				}
				if err == nil {
					_, err = conn.Write([]byte("proxy response after EOF"))
				}
				result <- err
			}()
			address := M.ParseSocksaddr(server.Addr().String())
			config := fmt.Sprintf(`{"log":{"disabled":true},"outbounds":[{"type":"desync","tag":"dpi","preset":"auto","mode":%q},{"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":%d,"detour":"dpi"}]}`, mode, address.Port)
			instance := regressionBox(t, config)
			proxy, _ := instance.Outbound().Outbound("proxy")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, err := proxy.DialContext(ctx, "tcp", M.ParseSocksaddr("203.0.113.9:443"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			if _, err = io.WriteString(conn, "application once"); err != nil {
				t.Fatal(err)
			}
			if err = N.CloseWrite(conn); err != nil {
				t.Fatal(err)
			}
			response, err := io.ReadAll(conn)
			if err != nil || string(response) != "proxy response after EOF" {
				t.Fatalf("response: %q %v", response, err)
			}
			if err = <-result; err != nil {
				t.Fatal(err)
			}
		})
	}
}
