package desync

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestTransformHTTPIndividualModifications(t *testing.T) {
	t.Parallel()
	const request = "GET /hello?q=1 HTTP/1.1\r\nHost: \tWWW.Example.COM:08443\t \r\nX-Other: Host: untouched\r\n\r\n"
	for _, tc := range []struct {
		name, mods, host string
	}{
		{"header case", "hcsmix", "hOsT: \tWWW.Example.COM:08443\t "},
		{"domain case", "dcsmix", "Host: \twWw.ExAmPlE.cOm:08443\t "},
		{"remove space", "rmspace", "Host:WWW.Example.COM:08443\t  \t"},
		{"all", "hcsmix,dcsmix,rmspace", "hOsT:wWw.ExAmPlE.cOm:08443\t  \t"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte(request)
			got, err := transformHTTP(input, tc.mods)
			if err != nil {
				t.Fatal(err)
			}
			want := "GET /hello?q=1 HTTP/1.1\r\n" + tc.host + "\r\nX-Other: Host: untouched\r\n\r\n"
			if string(got) != want || string(input) != request {
				t.Fatalf("got %q, want %q; input %q", got, want, input)
			}
			r, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(got)))
			if err != nil || !strings.EqualFold(r.Host, "www.example.com:08443") {
				t.Fatalf("Host semantics lost: request=%v error=%v", r, err)
			}
		})
	}
}

func TestTransformHTTPPreservesBodyAndPipeline(t *testing.T) {
	t.Parallel()
	for _, chunked := range []bool{false, true} {
		name := "content length"
		if chunked {
			name = "chunked"
		}
		t.Run(name, func(t *testing.T) {
			body := "Host: do-not-touch\r\n\r\n"
			framing := "Content-Length: 22\r\n"
			wireBody := body
			if chunked {
				framing = "Transfer-Encoding: chunked\r\nTrailer: X-Trailer\r\n"
				wireBody = "16\r\n" + body + "\r\n0\r\nX-Trailer: Host: unchanged\r\n\r\n"
			}
			pipeline := "GET /next HTTP/1.1\r\nHost: NEXT.EXAMPLE\r\n\r\n"
			header := "POST / HTTP/1.1\r\nhost:\t EXAMPLE.com:8080\r\n" + framing + "\r\n"
			input := []byte(header + wireBody + pipeline)
			before := bytes.Clone(input)
			got, err := transformHTTP(input, "rmspace,hcsmix,dcsmix")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(input, before) || !bytes.Equal(got[len(header):], before[len(header):]) {
				t.Fatal("body, trailers, pipeline or input buffer changed")
			}
			reader := bufio.NewReader(bytes.NewReader(got))
			r, err := http.ReadRequest(reader)
			if err != nil {
				t.Fatal(err)
			}
			readBody, err := io.ReadAll(r.Body)
			if err != nil || string(readBody) != body {
				t.Fatalf("body semantics changed: %q, %v", readBody, err)
			}
			next, err := http.ReadRequest(reader)
			if err != nil || next.Host != "NEXT.EXAMPLE" {
				t.Fatalf("pipeline changed: %v, %v", next, err)
			}
		})
	}
}

func TestTransformHTTPPreservesIPv6AndPorts(t *testing.T) {
	t.Parallel()
	for _, host := range []string{"[2001:DB8:ABCD::EF]:00443", "[::FFFF:192.0.2.1]", "127.0.0.1:8080", "example.com:00080"} {
		t.Run(host, func(t *testing.T) {
			got, err := transformHTTP([]byte("GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), "dcsmix,rmspace")
			if err != nil {
				t.Fatal(err)
			}
			if host[0] == '[' || host[0] == '1' {
				if !bytes.Contains(got, []byte("Host:"+host+" \r\n")) {
					t.Fatalf("literal address or port changed: %q", got)
				}
			} else if !bytes.Contains(got, []byte(":00080 \r\n")) {
				t.Fatalf("explicit port changed: %q", got)
			}
		})
	}
}

func TestTransformHTTPPassThrough(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, data, mods string
	}{
		{"disabled malformed", "GET / INVALID\nHost: x", ""},
		{"binary", "\x00\x01GET / HTTP/1.1\r\nHost: EXAMPLE.com\r\n\r\n", "hcsmix"},
		{"TLS", "\x16\x03\x01\x00\x40Host: EXAMPLE.com\r\n\r\n", "dcsmix"},
		{"response", "HTTP/1.1 200 OK\r\nHost: EXAMPLE.com\r\n\r\n", "rmspace"},
		{"hostless", "GET / HTTP/1.0\r\nX-Other: ok\r\n\r\nHost: this-is-body", "hcsmix,dcsmix,rmspace"},
		{"unknown method", "CUSTOM / HTTP/1.1\r\nHost: example.com\r\n\r\n", "hcsmix"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte(tc.data)
			got, err := transformHTTP(input, tc.mods)
			if err != nil || !bytes.Equal(got, input) || string(input) != tc.data {
				t.Fatalf("pass-through changed data: %q, %v", got, err)
			}
		})
	}
}

func TestTransformHTTPRejectsUnsafeRequests(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, request string
	}{
		{"duplicate host", "GET / HTTP/1.1\r\nHost: example.com\r\nhOsT: example.com\r\n\r\n"},
		{"absolute target", "GET http://other.example/ HTTP/1.1\r\nHost: example.com\r\n\r\n"},
		{"CONNECT", "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"},
		{"bad asterisk", "GET * HTTP/1.1\r\nHost: example.com\r\n\r\n"},
		{"incomplete", "GET / HTTP/1.1\r\nHost: example.com\r\n"},
		{"LF only", "GET / HTTP/1.1\nHost: example.com\n\n"},
		{"mixed LF", "GET / HTTP/1.1\r\nHost: example.com\nX-Bad: yes\r\n\r\n"},
		{"obs fold", "GET / HTTP/1.1\r\nHost: example.com\r\n .evil.example\r\n\r\n"},
		{"space before colon", "GET / HTTP/1.1\r\nHost : example.com\r\n\r\n"},
		{"bad version", "GET / HTTP/2.0\r\nHost: example.com\r\n\r\n"},
		{"bad length", "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: nope\r\n\r\n"},
		{"conflicting lengths", "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte(tc.request)
			got, err := transformHTTP(input, "hcsmix,dcsmix,rmspace")
			if err == nil || got != nil || string(input) != tc.request {
				t.Fatalf("unsafe request not safely rejected: %q, %v", got, err)
			}
		})
	}
	for _, host := range []string{"", "user@example.com", "two hosts", "example.com:", "example.com:abc", "example.com:65536", "[2001:db8::1", "[example.com]", "2001:db8::1", "[::1]:"} {
		t.Run("host_"+host, func(t *testing.T) {
			if _, err := transformHTTP([]byte("GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), "dcsmix"); err == nil {
				t.Fatal("invalid Host accepted")
			}
		})
	}
	for _, mods := range []string{"unknown", "hcsmix,", ",rmspace"} {
		t.Run("mods_"+mods, func(t *testing.T) {
			if _, err := transformHTTP(nil, mods); err == nil {
				t.Fatal("invalid modification accepted")
			}
		})
	}
}

func TestTransformHTTPSafeForms(t *testing.T) {
	t.Parallel()
	for _, request := range []string{
		"OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"GET / HTTP/1.0\r\nHost:example.com\r\n\r\n",
	} {
		got, err := transformHTTP([]byte(request), "hcsmix,rmspace")
		if err != nil || !bytes.Contains(got, []byte("hOsT:")) {
			t.Fatalf("safe request rejected: %q, %v", got, err)
		}
	}
}

func FuzzTransformHTTP(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nHost: body"))
	f.Add([]byte("\x16\x03\x01binary"))
	f.Fuzz(func(t *testing.T, input []byte) {
		before := bytes.Clone(input)
		got, err := transformHTTP(input, "hcsmix,dcsmix,rmspace")
		if !bytes.Equal(input, before) {
			t.Fatal("input mutated")
		}
		if err == nil {
			if len(got) != len(input) {
				t.Fatal("transformation shifted body offsets")
			}
			if end := bytes.Index(input, []byte("\r\n\r\n")); end >= 0 && !bytes.Equal(got[end+4:], input[end+4:]) {
				t.Fatal("transformation changed data following headers")
			}
		}
	})
}
