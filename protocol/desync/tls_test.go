package desync

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	engine "github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestAdaptiveRetriesRealTLSBeforeResponse(t *testing.T) {
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certServer.TLS.Certificates[0]
	pool := x509.NewCertPool()
	pool.AddCert(certServer.Certificate())
	certServer.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverResult := make(chan error, 1)
	go func() {
		first, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		_ = first.SetDeadline(time.Now().Add(2 * time.Second))
		header := make([]byte, 5)
		_, err = io.ReadFull(first, header)
		if err == nil {
			_, err = io.CopyN(io.Discard, first, int64(binary.BigEndian.Uint16(header[3:])))
		}
		_ = first.Close()
		if err != nil {
			serverResult <- err
			return
		}
		second, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer second.Close()
		server := tls.Server(second, &tls.Config{Certificates: []tls.Certificate{certificate}})
		if err = server.HandshakeContext(ctx); err == nil {
			_, err = server.Write([]byte("application response"))
		}
		serverResult <- err
	}()
	a := adaptiveForTest(t)
	var dials atomic.Int32
	dial := func(ctx, lifetime context.Context, d M.Socksaddr, o option.DesyncOptions) (net.Conn, error) {
		dials.Add(1)
		var dialer net.Dialer
		conn, err := dialer.DialContext(ctx, "tcp", d.String())
		if err != nil {
			return nil, err
		}
		wrapped, err := engine.NewConn(lifetime, conn, o)
		if err != nil {
			conn.Close()
		}
		return wrapped, err
	}
	conn, err := a.DialContext(ctx, M.ParseSocksaddr(listener.Addr().String()), 0, dial)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := tls.Client(conn, &tls.Config{ServerName: "example.com", RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err = client.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if N.UnwrapWriter(conn) != conn || N.SyscallAvailableForWrite(conn) {
		t.Fatal("engine handoff bypassed Adaptive retry/observation ownership")
	}
	response := make([]byte, len("application response"))
	if _, err = io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "application response" || dials.Load() != 2 {
		t.Fatalf("response %q dials=%d", response, dials.Load())
	}
	if err = <-serverResult; err != nil {
		t.Fatal(err)
	}
}
