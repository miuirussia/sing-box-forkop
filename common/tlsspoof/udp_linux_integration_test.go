//go:build linux && integration

package tlsspoof

import (
	"bytes"
	"net"
	"os"
	"testing"
	"time"
)

func TestUDPInjectorFragmentedDatagram(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("CAP_NET_RAW required")
	}
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			host := "127.0.0.1:0"
			mtu := 576
			if network == "udp6" {
				host = "[::1]:0"
				mtu = 1280
			}
			server, err := net.ListenPacket(network, host)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			_ = server.SetDeadline(time.Now().Add(2 * time.Second))
			raw, err := net.Dial(network, server.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			injector, err := NewUDPInjector(raw, server.LocalAddr())
			if err != nil {
				t.Fatal(err)
			}
			defer injector.Close()
			if injector.mtu <= 0 {
				t.Fatal("path MTU was not discovered")
			}
			injector.mtu = mtu
			payload := bytes.Repeat([]byte("raw UDP fake fragmented payload"), 200)
			if err = injector.Send(payload, 64); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 10000)
			n, from, err := server.ReadFrom(buf)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf[:n], payload) {
				t.Fatal("UDP fragments did not reassemble exactly")
			}
			if from.String() != raw.LocalAddr().String() {
				t.Fatalf("source tuple %s want %s", from, raw.LocalAddr())
			}
		})
	}
}
