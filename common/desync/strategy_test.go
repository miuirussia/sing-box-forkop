package desync

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestSegmentOrder(t *testing.T) {
	for _, tc := range []struct {
		name, spec string
		want       []int
	}{
		{"forward", "forward", []int{0, 1, 2, 3}},
		{"reverse", "reverse", []int{3, 2, 1, 0}},
		{"host last", "sni_last", []int{0, 3, 1, 2}},
		{"permutation", "2,1,4,3", []int{1, 0, 3, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := segmentOrder(tc.spec, []int{0, 5, 10, 15, 20}, 7, 12)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("order=%v err=%v", got, err)
			}
		})
	}
	for _, spec := range []string{"1,1,3,4", "1,2", "0,2,3,4", "5,2,3,4"} {
		if _, err := segmentOrder(spec, []int{0, 5, 10, 15, 20}, 7, 12); err == nil {
			t.Fatalf("accepted %q", spec)
		}
	}
}

func TestConnIndependentTLSRecordAndTCPCuts(t *testing.T) {
	hello := testHello(t, "www.example.com")
	target := &shortConn{chunk: 4096}
	conn, err := NewConn(context.Background(), target, option.DesyncOptions{Mode: "multi_split", SplitPos: "sniext+1,endhost-1", TLSRecFirst: true, TLSRecPos: "midsld"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	got := target.bytes()
	before, _, _ := clientHello(hello)
	after, complete, err := clientHello(got)
	if err != nil || !complete || !bytes.Equal(before.handshake, after.handshake) {
		t.Fatal("record transformation changed ClientHello")
	}
	if len(got) != len(hello)+5 {
		t.Fatalf("wire size=%d, want %d", len(got), len(hello)+5)
	}
	cut, _ := positions(hello, "midsld")
	if got[cut[0]] != 22 || got[cut[0]+1] != 3 {
		t.Fatal("TLS record was not cut at its independent position")
	}
}

func TestHostDecoyPreservesTLSRecordHeadersAndOriginal(t *testing.T) {
	hello := testHello(t, "www.example.com")
	cut, _ := positions(hello, "midsld")
	split, err := recordSplit(hello, cut)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(split)
	got, err := hostDecoy(split, "decoy.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(split) || !bytes.Equal(split, original) {
		t.Fatal("decoy changed original or wire length")
	}
	v, complete, err := clientHello(got)
	if err != nil || !complete {
		t.Fatalf("invalid decoy ClientHello: %v", err)
	}
	hp, err := tlsPositions(helloView{handshake: v.handshake, wire: identity(len(v.handshake))})
	if err != nil || string(v.handshake[hp.start:hp.end]) != "aaaa.decoy.test" {
		t.Fatalf("unexpected decoy hostname: %q, %v", v.handshake[hp.start:hp.end], err)
	}
	for p := 0; p < len(split); {
		if !bytes.Equal(got[p:p+5], split[p:p+5]) {
			t.Fatal("decoy changed record header")
		}
		p += 5 + int(split[p+3])<<8 + int(split[p+4])
	}
}

func TestConnNumericTLSRecordCutsWithoutSNI(t *testing.T) {
	hello := []byte{22, 3, 3, 0, 4, 1, 0, 0, 0}
	target := &shortConn{chunk: 4096}
	o, err := option.NormalizeDesyncOptions(option.DesyncOptions{Mode: "tlsrec", TLSRecPos: "6"})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := NewConn(context.Background(), target, o)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	got := target.bytes()
	if len(got) != len(hello)+5 {
		t.Fatal("unused default split_pos suppressed numeric TLS record cuts")
	}
	v, complete, err := clientHello(got)
	if err != nil || !complete || !bytes.Equal(v.handshake, hello[5:]) {
		t.Fatal("numeric record cuts changed handshake bytes")
	}
}

func TestHostDecoyDoesNotCopyHTTPBody(t *testing.T) {
	header := []byte("POST / HTTP/1.1\r\nHost: www.example.com\r\nContent-Length: 4\r\n\r\n")
	b := append(bytes.Clone(header), []byte("DATA")...)
	got, err := hostDecoy(b, "decoy.test")
	if err != nil || len(got) != len(header) || bytes.Contains(got, []byte("DATA")) || !bytes.Contains(b, []byte("www.example.com")) {
		t.Fatalf("invalid HTTP decoy: %q, %v", got, err)
	}
}

func TestConnHTTPTransformWithoutSegmentation(t *testing.T) {
	target := &shortConn{chunk: 4096}
	conn, err := NewConn(context.Background(), target, option.DesyncOptions{Mode: "none", HTTPMod: "hcsmix,rmspace"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	b := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if _, err = conn.Write(b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(target.bytes(), []byte("hOsT:example.com ")) {
		t.Fatalf("Host was not transformed: %q", target.bytes())
	}
}
