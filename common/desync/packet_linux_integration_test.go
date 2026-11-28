//go:build linux && integration

package desync

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/sagernet/sing/common/control"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

type capturedPacket struct {
	seq              uint32
	ack              uint32
	flags            byte
	ttl              byte
	window           uint16
	src, dst         uint16
	payload, options []byte
	fragment         bool
	version          byte
}

func capturePackets(t *testing.T, action func()) []capturedPacket {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("CAP_NET_RAW/CAP_NET_ADMIN required")
	}
	if _, err := exec.LookPath("tcpdump"); err != nil {
		t.Skip("tcpdump required")
	}
	path := filepath.Join(t.TempDir(), "capture.pcap")
	cmd := exec.Command("tcpdump", "--immediate-mode", "-i", "lo", "-n", "-U", "-B", "8192", "-s", "4096", "-w", path, "ip or ip6")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	ready := make(chan struct{})
	go func() {
		s := bufio.NewScanner(stderr)
		for s.Scan() {
			if strings.Contains(s.Text(), "listening on") {
				close(ready)
				_, _ = io.Copy(io.Discard, stderr)
				return
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("capture did not become ready")
	}
	action()
	time.Sleep(50 * time.Millisecond)
	_ = cmd.Process.Signal(os.Interrupt)
	if err = cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 24 {
		t.Fatal("empty pcap")
	}
	var order binary.ByteOrder = binary.LittleEndian
	if binary.LittleEndian.Uint32(data) != 0xa1b2c3d4 {
		order = binary.BigEndian
	}
	if order.Uint32(data[20:24]) != 1 {
		t.Fatalf("expected Ethernet pcap, link %d", order.Uint32(data[20:24]))
	}
	var result []capturedPacket
	for p := 24; p+16 <= len(data); {
		n := int(order.Uint32(data[p+8:]))
		p += 16
		if n > len(data)-p {
			t.Fatal("truncated pcap")
		}
		frame := data[p : p+n]
		p += n
		if len(frame) < 14 {
			continue
		}
		ip := frame[14:]
		if len(ip) < 20 {
			continue
		}
		packet := capturedPacket{version: ip[0] >> 4}
		off := 0
		proto := byte(0)
		if packet.version == 4 {
			off = int(ip[0]&15) * 4
			packet.ttl = ip[8]
			proto = ip[9]
			fragment := binary.BigEndian.Uint16(ip[6:])
			packet.fragment = fragment&0x3fff != 0
			if fragment&0x1fff != 0 {
				result = append(result, packet)
				continue
			}
		} else if packet.version == 6 {
			if len(ip) < 40 {
				continue
			}
			off = 40
			proto = ip[6]
			packet.ttl = ip[7]
			for (proto == 0 || proto == 60 || proto == 44) && off+8 <= len(ip) {
				typ := proto
				proto = ip[off]
				if typ == 44 {
					packet.fragment = true
					if binary.BigEndian.Uint16(ip[off+2:])&0xfff8 != 0 {
						proto = 255
						break
					}
					off += 8
				} else {
					off += 8 * (int(ip[off+1]) + 1)
				}
			}
		} else {
			continue
		}
		if proto == 6 && off+20 <= len(ip) {
			tcp := ip[off:]
			hlen := int(tcp[12]>>4) * 4
			if hlen < 20 || hlen > len(tcp) {
				continue
			}
			packet.src = binary.BigEndian.Uint16(tcp)
			packet.dst = binary.BigEndian.Uint16(tcp[2:])
			packet.seq = binary.BigEndian.Uint32(tcp[4:])
			packet.ack = binary.BigEndian.Uint32(tcp[8:])
			packet.flags = tcp[13]
			packet.window = binary.BigEndian.Uint16(tcp[14:])
			packet.options = append([]byte(nil), tcp[20:hlen]...)
			packet.payload = append([]byte(nil), tcp[hlen:]...)
			result = append(result, packet)
		} else if packet.fragment {
			result = append(result, packet)
		}
	}
	return result
}
func runCapturedHTTP(t *testing.T, host string, o option.DesyncOptions) ([]capturedPacket, []byte, uint16) {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	received := make(chan []byte, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		b, _ := io.ReadAll(c)
		received <- b
	}()
	real := []byte("POST / HTTP/1.1\r\nHost: www.example.com\r\nContent-Length: 4\r\n\r\nDATA")
	packets := capturePackets(t, func() {
		hook, err := SocketControl(o)
		if err != nil {
			t.Fatal(err)
		}
		dialer := net.Dialer{Control: hook, Timeout: time.Second}
		raw, err := dialer.DialContext(context.Background(), "tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		c, err := NewConn(context.Background(), raw, o)
		if err != nil {
			raw.Close()
			t.Fatal(err)
		}
		defer c.Close()
		if _, err = c.Write(real); err != nil {
			t.Fatal(err)
		}
		if half, ok := c.(interface{ CloseWrite() error }); ok {
			if err = half.CloseWrite(); err != nil {
				t.Fatal(err)
			}
		} else {
			_ = c.Close()
		}
		select {
		case got := <-received:
			if !bytes.Equal(got, real) {
				t.Fatalf("server received changed/repeated request: %q", got)
			}
		case <-time.After(6 * time.Second):
			t.Fatal("server stream timeout")
		}
	})
	return packets, real, port
}
func TestLinuxPacketDisorderOverlapAndWindow(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			o := option.DesyncOptions{Mode: "multi_disorder", SplitPos: "host+1,midsld,endhost-1", SeqOvl: 3, WSize: 1234}
			packets, real, port := runCapturedHTTP(t, host, o)
			cuts, err := positions(real, o.SplitPos)
			if err != nil {
				t.Fatal(err)
			}
			var data []capturedPacket
			for _, p := range packets {
				if p.dst == port && len(p.payload) > 0 {
					data = append(data, p)
				}
			}
			if len(data) < 4 {
				t.Fatalf("not enough TCP segments: %d", len(data))
			}
			if !bytes.Equal(data[0].payload, real[cuts[len(cuts)-1]-3:]) {
				t.Fatalf("first segment is not reversed tail: %q", data[0].payload)
			}
			if data[0].window != 1234 {
				t.Fatalf("advertised window %d", data[0].window)
			}
			inverted := false
			for i := 1; i < len(data); i++ {
				if int32(data[i].seq-data[i-1].seq) < 0 {
					inverted = true
					break
				}
			}
			if !inverted {
				t.Fatal("capture has no inverted sequence numbers")
			}
		})
	}
}

func TestLinuxPacketSegmentPermutationsAndInterleavedFakes(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		for _, placement := range []string{"between", "before_between"} {
			t.Run(host+"/"+placement, func(t *testing.T) {
				fake := []byte("INTERLEAVED-FAKE")
				o := option.DesyncOptions{Mode: "fake_split", SplitPos: "host+1,endhost-1", SegmentOrder: "2,1,3", FakePlacement: placement, FakePayload: base64.StdEncoding.EncodeToString(fake), TTL: 64, Repeats: 1, WSize: 4321}
				packets, real, port := runCapturedHTTP(t, host, o)
				cuts, err := positions(real, o.SplitPos)
				if err != nil {
					t.Fatal(err)
				}
				bounds := []int{0, cuts[0], cuts[1], len(real)}
				var burst []capturedPacket
				for _, p := range packets {
					if p.dst == port && len(p.payload) > 0 && p.window == 4321 {
						burst = append(burst, p)
					}
				}
				wantCount := 5
				if placement == "before_between" {
					wantCount++
				}
				if len(burst) != wantCount {
					t.Fatalf("raw burst has %d packets, want %d", len(burst), wantCount)
				}
				at := 0
				if placement == "before_between" {
					if !bytes.Equal(burst[at].payload, fake) {
						t.Fatal("missing leading fake")
					}
					at++
				}
				var firstSeq uint32
				for step, index := range []int{1, 0, 2} {
					p := burst[at]
					if !bytes.Equal(p.payload, real[bounds[index]:bounds[index+1]]) {
						t.Fatalf("wrong segment at step %d: %q", step, p.payload)
					}
					if index == 0 {
						firstSeq = p.seq
					}
					at++
					if step < 2 {
						if !bytes.Equal(burst[at].payload, fake) {
							t.Fatal("fake missing between real segments")
						}
						at++
					}
				}
				for _, p := range burst {
					if bytes.Equal(p.payload, fake) && int32(p.seq+uint32(len(fake))-firstSeq) > 0 {
						t.Fatal("interleaved fake overlaps real sequence range")
					}
				}
			})
		}
	}
}

func TestLinuxPacketHostReplacementDecoy(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			o := option.DesyncOptions{Mode: "hostfakesplit", HostFakeMode: "replace", SplitPos: "midsld", FakeHost: "decoy.test", Fooling: "none", TTL: 64, Repeats: 1}
			packets, real, port := runCapturedHTTP(t, host, o)
			decoy, err := hostDecoy(real, o.FakeHost)
			if err != nil {
				t.Fatal(err)
			}
			var decoySeq, realSeq uint32
			foundDecoy, foundReal := false, false
			for _, p := range packets {
				if p.dst != port {
					continue
				}
				if bytes.Equal(p.payload, decoy) {
					decoySeq, foundDecoy = p.seq, true
				} else if len(p.payload) > 0 && bytes.HasPrefix(p.payload, []byte("POST")) {
					realSeq, foundReal = p.seq, true
				}
			}
			if !foundDecoy || !foundReal || decoySeq != realSeq {
				t.Fatalf("host decoy missing or wrong sequence: decoy=%d/%v real=%d/%v", decoySeq, foundDecoy, realSeq, foundReal)
			}
		})
	}
}
func TestLinuxPacketFakeFoolingNeverServerStream(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		for _, fooling := range []string{"", "badseq", "badack", "badsum", "md5", "md5_badack", "badseq_badack_badsum", "datanoack", "none", "ts", "badtimestamp", "hopbyhop", "destopt", "ipfrag"} {
			if host == "127.0.0.1" && (fooling == "hopbyhop" || fooling == "destopt") {
				continue
			}
			t.Run(host+"/"+fooling, func(t *testing.T) {
				o := option.DesyncOptions{Mode: "fake_split", SplitPos: "host+1", FakePayload: base64.StdEncoding.EncodeToString([]byte("FAKE-MUST-NEVER-BECOME-STREAM")), Fooling: fooling, TTL: 3, Repeats: 2}
				packets, _, port := runCapturedHTTP(t, host, o)
				var realSeq uint32
				fakeN := 0
				for _, p := range packets {
					if p.dst == port && len(p.payload) > 0 && bytes.HasPrefix(p.payload, []byte("POST")) {
						realSeq = p.seq
						break
					}
				}
				if realSeq == 0 {
					t.Fatal("real stream start not captured")
				}
				for _, p := range packets {
					if p.dst == port && bytes.Contains(p.payload, []byte("FAKE-MUST")) {
						fakeN++
						if int32(p.seq+uint32(len(p.payload))-realSeq) > 0 {
							t.Fatalf("fake overlaps future stream seq=%d real=%d", p.seq, realSeq)
						}
						if p.ttl != 3 {
							t.Fatalf("fake ttl %d", p.ttl)
						}
						switch fooling {
						case "datanoack":
							if p.flags&0x10 != 0 {
								t.Fatal("ACK not cleared")
							}
						case "md5_badack":
							if !bytes.Contains(p.options, []byte{19, 18}) {
								t.Fatal("MD5 option missing")
							}
						}
					}
				}
				if fakeN != 2 {
					t.Fatalf("fake packets %d want2", fakeN)
				}
			})
		}
	}
}
func TestLinuxPacketIPFragments(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			packets, _, _ := runCapturedHTTP(t, host, option.DesyncOptions{Mode: "split", SplitPos: "host+1", IPFrag: 24})
			n := 0
			for _, p := range packets {
				if p.fragment {
					n++
				}
			}
			if n < 2 {
				t.Fatalf("no IP fragments captured: %d", n)
			}
		})
	}
}
func optionScale(options []byte) (int, bool) {
	for i := 0; i < len(options); {
		if options[i] == 0 {
			break
		}
		if options[i] == 1 {
			i++
			continue
		}
		if i+1 >= len(options) {
			break
		}
		n := int(options[i+1])
		if n < 2 || i+n > len(options) {
			break
		}
		if options[i] == 3 && n == 3 {
			return int(options[i+2]), true
		}
		i += n
	}
	return 0, false
}
func TestLinuxPacketPreSYNControls(t *testing.T) {
	for _, scale := range []int{0, 1, 7, 14} {
		t.Run(fmt.Sprint(scale), func(t *testing.T) {
			o := option.DesyncOptions{Mode: "split", SplitPos: "host+1", SynData: base64.StdEncoding.EncodeToString([]byte("FAKE-SYN-DATA")), WScale: scale, WScaleExplicit: true}
			packets, _, port := runCapturedHTTP(t, "127.0.0.1", o)
			fakeIndex, realIndex := -1, -1
			var src uint16
			for i, p := range packets {
				if p.dst != port || p.flags&2 == 0 || p.flags&0x10 != 0 {
					continue
				}
				if bytes.Equal(p.payload, []byte("FAKE-SYN-DATA")) {
					fakeIndex = i
					src = p.src
				} else if len(p.payload) == 0 && realIndex < 0 {
					realIndex = i
					if got, ok := optionScale(p.options); !ok || got != scale {
						t.Fatalf("SYN scale %d present %v want%d", got, ok, scale)
					}
				}
			}
			if fakeIndex < 0 || realIndex <= fakeIndex {
				t.Fatalf("SYN payload order fake=%d real=%d", fakeIndex, realIndex)
			}
			if packets[realIndex].src != src {
				t.Fatal("SYN tuple differs")
			}
		})
	}
}
func TestLinuxPacketAutoTTL(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			packets, _, port := runCapturedHTTP(t, host, option.DesyncOptions{Mode: "fake", FakePayload: base64.StdEncoding.EncodeToString([]byte("TTL-OBSERVED-FAKE")), Fooling: "badseq", TTL: 32, AutoTTL: true})
			seen := false
			for _, p := range packets {
				if p.dst == port && bytes.Equal(p.payload, []byte("TTL-OBSERVED-FAKE")) {
					seen = true
					if p.ttl != 1 {
						t.Fatalf("loopback route TTL %d want1", p.ttl)
					}
				}
			}
			if !seen {
				t.Fatal("no TTL fake captured")
			}
		})
	}
}

func TestLinuxPacketLargeFakeIsSegmented(t *testing.T) {
	fake := bytes.Repeat([]byte("LARGE-FAKE"), 1000)
	packets, _, port := runCapturedHTTP(t, "127.0.0.1", option.DesyncOptions{Mode: "fake", FakePayload: base64.StdEncoding.EncodeToString(fake), TTL: 3})
	var segments []capturedPacket
	var realSeq uint32
	for _, p := range packets {
		if p.dst != port || len(p.payload) == 0 {
			continue
		}
		if bytes.HasPrefix(p.payload, []byte("POST")) {
			realSeq = p.seq
			continue
		}
		segments = append(segments, p)
	}
	if realSeq == 0 {
		t.Fatal("real stream start missing from capture")
	}
	if len(segments) != 9 {
		t.Fatalf("large fake produced %d segments want9", len(segments))
	}
	size := 0
	for i, p := range segments {
		if len(p.payload) > 1120 || p.ttl != 3 {
			t.Fatalf("invalid raw segment length=%d ttl=%d", len(p.payload), p.ttl)
		}
		if int32(p.seq+uint32(len(p.payload))-realSeq) > 0 {
			t.Fatal("large fake overlaps real stream")
		}
		if i > 0 && p.seq != segments[i-1].seq+uint32(len(segments[i-1].payload)) {
			t.Fatal("fake sequence range not contiguous")
		}
		size += len(p.payload)
	}
	if size != len(fake) {
		t.Fatalf("fake truncated %d want%d", size, len(fake))
	}
}

func TestLinuxWindowScaleRestoresReceiveBuffer(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("CAP_NET_ADMIN required")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := listener.Accept()
		if err == nil {
			defer c.Close()
			_, _ = io.Copy(io.Discard, c)
		}
	}()
	o := option.DesyncOptions{Mode: "split", SplitPos: "1", WScale: 14, WScaleExplicit: true}
	hook, err := SocketControl(o)
	if err != nil {
		t.Fatal(err)
	}
	before := 0
	dialer := net.Dialer{Control: func(network, address string, raw syscall.RawConn) error {
		if err := control.Raw(raw, func(fd uintptr) error {
			var err error
			before, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
			return err
		}); err != nil {
			return err
		}
		return hook(network, address, raw)
	}}
	raw, err := dialer.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewConn(context.Background(), raw, o)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	defer c.Close()
	after := 0
	if err = control.Conn(raw.(syscall.Conn), func(fd uintptr) error {
		var err error
		after, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("receive buffer not restored: %d -> %d", before, after)
	}
	_ = c.Close()
	<-done
}
