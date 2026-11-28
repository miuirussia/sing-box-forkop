//go:build integration

package desync

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	engine "github.com/sagernet/sing-box/common/desync"
)

// Validate alone cannot tell whether a generated record cut or fake size is
// usable. Every automatic candidate must also carry a real, modern ClientHello.
func TestAdaptiveCatalogRealTLSHandshake(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "catalogue TLS intact")
	}))
	defer server.Close()
	o := strategyForTest(t, `{"preset":"auto"}`)
	for _, candidate := range adaptiveCatalog(o) {
		t.Run(strategyID(candidate), func(t *testing.T) {
			rawMode := strings.Contains(candidate.Mode, "disorder") || strings.Contains(candidate.Mode, "fake") || strings.Contains(candidate.Mode, "oob") || candidate.SegmentOrder != ""
			if rawMode && os.Geteuid() != 0 {
				t.Skip("raw TCP privileges required")
			}
			raw, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
			wrapped, err := engine.NewConn(context.Background(), raw, candidate)
			if err != nil {
				t.Fatal(err)
			}
			defer wrapped.Close()
			client := tls.Client(wrapped, &tls.Config{ServerName: "www.example.com", InsecureSkipVerify: true})
			if err = client.Handshake(); err != nil {
				t.Fatalf("automatic candidate failed: %+v: %v", candidate, err)
			}
			if _, err = io.WriteString(client, "GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			reply, err := io.ReadAll(client)
			if err != nil || !bytes.Contains(reply, []byte("catalogue TLS intact")) {
				t.Fatalf("application stream failed: %q, %v", reply, err)
			}
		})
	}
}
