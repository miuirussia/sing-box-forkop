//go:build with_gvisor

package wireguard

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/phobos"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service/pause"
)

// This test uses the unmodified upstream executable and real WireGuard crypto.
func TestPhobosInterop(t *testing.T) {
	binary := os.Getenv("PHOBOS_OBFUSCATOR")
	if binary == "" {
		t.Skip("set PHOBOS_OBFUSCATOR to upstream wg-obfuscator")
	}
	for _, mode := range []string{"STUN", "NONE", "AUTO", "MEDIA"} {
		for _, partial := range []int{0, 16} {
			t.Run(fmt.Sprintf("%s/%d", mode, partial), func(t *testing.T) {
				ctx := pause.WithDefaultManager(context.Background())
				clientPrivate, clientPublic := testKeyPair(t)
				serverPrivate, serverPublic := testKeyPair(t)
				freePort := func() uint16 {
					p, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
					if err != nil {
						t.Fatal(err)
					}
					port := uint16(p.LocalAddr().(*net.UDPAddr).Port)
					p.Close()
					return port
				}
				serverPort, obfuscatorPort := freePort(), freePort()
				server := startTestEndpoint(t, EndpointOptions{Context: ctx, Logger: logger.NOP(), Dialer: listenDialer{}, Address: []netip.Prefix{netip.MustParsePrefix("10.77.0.1/32")}, PrivateKey: serverPrivate, ListenPort: serverPort, Peers: []PeerOptions{{PublicKey: clientPublic, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.77.0.2/32")}}}}, false)
				// Upstream defaults MEDIA to partial=16 even when passed zero.
				effectivePartial := partial
				if mode == "MEDIA" && partial == 0 {
					effectivePartial = 16
				}
				cmd := exec.Command(binary, "-p", fmt.Sprint(obfuscatorPort), "-t", fmt.Sprintf("127.0.0.1:%d", serverPort), "-k", "interop-key", "-a", mode, "-O", fmt.Sprint(effectivePartial), "-T", "1")
				logFile, err := os.CreateTemp(t.TempDir(), "obfuscator-log")
				if err != nil {
					t.Fatal(err)
				}
				cmd.Stdout = logFile
				cmd.Stderr = logFile
				if err = cmd.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					cmd.Process.Kill()
					cmd.Wait()
					logFile.Close()
					if t.Failed() {
						data, _ := os.ReadFile(logFile.Name())
						t.Log(string(data))
					}
				})
				deadline := time.Now().Add(3 * time.Second)
				for {
					data, _ := os.ReadFile(logFile.Name())
					if strings.Contains(string(data), "successfully started") {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("obfuscator did not start: %s", data)
					}
					time.Sleep(10 * time.Millisecond)
				}
				o, err := phobos.Normalize(&option.PhobosObfuscationOptions{Key: "interop-key", Masking: mode, ObfuscateBytes: &effectivePartial})
				if err != nil {
					t.Fatal(err)
				}
				var clientDialer N.Dialer = listenDialer{}
				host := "127.0.0.1"
				if partial == 16 {
					clientDialer = &proxyDialer{}
					host = "wg.test"
				}
				client := startTestEndpoint(t, EndpointOptions{Context: ctx, Logger: logger.NOP(), Dialer: clientDialer, MTU: 1280, Address: []netip.Prefix{netip.MustParsePrefix("10.77.0.2/32")}, PrivateKey: clientPrivate, Phobos: o, Peers: []PeerOptions{{Endpoint: M.ParseSocksaddrHostPort(host, obfuscatorPort), PublicKey: serverPublic, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.77.0.1/32")}}}}, partial == 16)
				s := server.tunDevice.(*stackDevice).stack
				addr := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 77, 0, 1}), Port: 12345}
				listener, err := gonet.ListenTCP(s, addr, ipv4.ProtocolNumber)
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				go func() {
					c, err := listener.Accept()
					if err == nil {
						defer c.Close()
						c.SetDeadline(time.Now().Add(10 * time.Second))
						io.Copy(c, c)
					}
				}()
				dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				tcpConn, err := client.DialContext(dialCtx, "tcp", M.ParseSocksaddrHostPort("10.77.0.1", 12345))
				if err != nil {
					t.Fatal(err)
				}
				defer tcpConn.Close()
				tcpConn.SetDeadline(time.Now().Add(5 * time.Second))
				payload := bytes.Repeat([]byte("phobos"), 500)
				if _, err = tcpConn.Write(payload); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(payload))
				if _, err = io.ReadFull(tcpConn, got); err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("TCP echo: %v", err)
				}
				udpServer, err := gonet.DialUDP(s, &addr, nil, ipv4.ProtocolNumber)
				if err != nil {
					t.Fatal(err)
				}
				defer udpServer.Close()
				go func() {
					buffer := make([]byte, 4096)
					udpServer.SetDeadline(time.Now().Add(5 * time.Second))
					n, remote, err := udpServer.ReadFrom(buffer)
					if err == nil {
						udpServer.WriteTo(buffer[:n], remote)
					}
				}()
				udpConn, err := client.DialContext(ctx, "udp", M.ParseSocksaddrHostPort("10.77.0.1", 12345))
				if err != nil {
					t.Fatal(err)
				}
				defer udpConn.Close()
				udpConn.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err = udpConn.Write(payload[:1200]); err != nil {
					t.Fatal(err)
				}
				n, err := udpConn.Read(got)
				if err != nil || !bytes.Equal(got[:n], payload[:1200]) {
					t.Fatalf("UDP echo: %v", err)
				}
				if !handshakeCompleted(client) {
					t.Fatal("WireGuard handshake did not complete")
				}
			})
		}
	}
}
