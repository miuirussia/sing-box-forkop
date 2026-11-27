//go:build linux && integration

package desync

import (
	"context"
	"encoding/base64"
	"github.com/sagernet/sing-box/option"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRawPermissionError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("run test binary as unprivileged UID to verify capability error")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 1)
			_, _ = conn.Read(buf)
		}
	}()
	raw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewConn(context.Background(), raw, option.DesyncOptions{Mode: "fake", FakePayload: base64.StdEncoding.EncodeToString([]byte("FAKE"))})
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if err == nil || !strings.Contains(err.Error(), "CAP_NET_") {
		t.Fatalf("missing actionable capability failure: %v", err)
	}
	_ = c.Close()
	<-done
}
