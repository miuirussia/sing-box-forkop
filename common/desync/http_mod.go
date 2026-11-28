package desync

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

// transformHTTP edits only the Host field in the first request header. Body
// bytes, trailers and subsequent pipelined requests are opaque to this function.
func transformHTTP(b []byte, mods string) ([]byte, error) {
	if mods == "" {
		return b, nil
	}
	var headerCase, domainCase, removeSpace bool
	for _, mod := range strings.Split(mods, ",") {
		switch strings.TrimSpace(mod) {
		case "hcsmix":
			headerCase = true
		case "dcsmix":
			domainCase = true
		case "rmspace":
			removeSpace = true
		default:
			return nil, fmt.Errorf("desync: unknown HTTP modification %q", mod)
		}
	}
	recognized := false
	for _, method := range []string{"GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH ", "TRACE "} {
		if bytes.HasPrefix(b, []byte(method)) {
			recognized = true
			break
		}
	}
	if !recognized {
		return b, nil
	}
	end := bytes.Index(b, []byte("\r\n\r\n"))
	if end < 0 {
		return nil, fmt.Errorf("desync: incomplete HTTP request headers (CRLF required)")
	}
	header := b[:end+2]
	lines := bytes.Split(header[:len(header)-2], []byte("\r\n"))
	parts := bytes.Split(lines[0], []byte(" "))
	if len(parts) != 3 || (string(parts[2]) != "HTTP/1.0" && string(parts[2]) != "HTTP/1.1") {
		return nil, fmt.Errorf("desync: malformed HTTP request line")
	}
	// Case changes to Host cannot safely stand alone when another authority
	// appears in the request target. Only origin-form and OPTIONS * are edited.
	if len(parts[1]) == 0 || (parts[1][0] != '/' && !(string(parts[0]) == "OPTIONS" && string(parts[1]) == "*")) || string(parts[0]) == "CONNECT" {
		return nil, fmt.Errorf("desync: unsafe HTTP request target for Host transformation")
	}
	hostStart, hostColon, hostEnd := -1, -1, -1
	offset := len(lines[0]) + 2
	for _, line := range lines[1:] {
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			return nil, fmt.Errorf("desync: malformed HTTP header or obsolete folding")
		}
		for _, c := range line[:colon] {
			if !httpModToken(c) {
				return nil, fmt.Errorf("desync: invalid HTTP header name")
			}
		}
		for _, c := range line[colon+1:] {
			if (c < 32 && c != '\t') || c == 127 {
				return nil, fmt.Errorf("desync: invalid HTTP header value (CRLF required)")
			}
		}
		if strings.EqualFold(string(line[:colon]), "host") {
			if hostStart >= 0 {
				return nil, fmt.Errorf("desync: duplicate HTTP Host is ambiguous")
			}
			hostStart, hostColon, hostEnd = offset, offset+colon, offset+len(line)
		}
		offset += len(line) + 2
	}
	// Parse framing too, without reading the body. This catches malformed
	// lengths and transfer encodings before emitting modified request bytes.
	if _, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b[:end+4]))); err != nil {
		return nil, fmt.Errorf("desync: malformed HTTP request: %w", err)
	}
	if hostStart < 0 {
		return b, nil
	}
	valueStart, valueEnd := hostColon+1, hostEnd
	for valueStart < valueEnd && (b[valueStart] == ' ' || b[valueStart] == '\t') {
		valueStart++
	}
	for valueEnd > valueStart && (b[valueEnd-1] == ' ' || b[valueEnd-1] == '\t') {
		valueEnd--
	}
	domainEnd, err := httpModDomainEnd(string(b[valueStart:valueEnd]))
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), b...)
	if headerCase {
		copy(out[hostStart:hostColon], "hOsT")
	}
	if domainCase {
		upper := false
		for p := valueStart; p < valueStart+domainEnd; p++ {
			c := out[p]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c >= 'a' && c <= 'z' {
				if upper {
					c -= 'a' - 'A'
				}
				out[p] = c
				upper = !upper
			}
		}
	}
	if removeSpace && valueStart > hostColon+1 {
		// Move leading OWS to trailing OWS: both are legal, and keeping the
		// length avoids shifting body and pipeline offsets.
		ows := append([]byte(nil), out[hostColon+1:valueStart]...)
		copy(out[hostColon+1:hostEnd], out[valueStart:hostEnd])
		copy(out[hostEnd-len(ows):hostEnd], ows)
	}
	return out, nil
}

func httpModToken(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))
}

// httpModDomainEnd validates a single authority and excludes its explicit port
// and bracketed IPv6 address from domain case mixing.
func httpModDomainEnd(host string) (int, error) {
	fail := func() (int, error) { return 0, fmt.Errorf("desync: invalid HTTP Host authority %q", host) }
	if host == "" {
		return fail()
	}
	domainEnd := len(host)
	port := ""
	if host[0] == '[' {
		end := strings.IndexByte(host, ']')
		if end < 0 {
			return fail()
		}
		addr, err := netip.ParseAddr(host[1:end])
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return fail()
		}
		if end+1 < len(host) {
			if host[end+1] != ':' {
				return fail()
			}
			port = host[end+2:]
			if port == "" {
				return fail()
			}
		}
		domainEnd = 0
	} else {
		if colon := strings.IndexByte(host, ':'); colon >= 0 {
			domainEnd = colon
			port = host[colon+1:]
			if port == "" {
				return fail()
			}
		}
		if domainEnd == 0 {
			return fail()
		}
		for _, c := range []byte(host[:domainEnd]) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
				return fail()
			}
		}
	}
	if port != "" {
		for _, c := range []byte(port) {
			if c < '0' || c > '9' {
				return fail()
			}
		}
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return fail()
		}
	}
	return domainEnd, nil
}
