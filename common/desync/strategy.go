package desync

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// segmentOrder returns indices into adjacent bounds; explicit orders must cover
// the actual segments exactly once, after marker sorting and deduplication.
func segmentOrder(spec string, bounds []int, hostStart, hostEnd int) ([]int, error) {
	n := len(bounds) - 1
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	switch spec {
	case "", "forward":
	case "reverse":
		for i, j := 0, n-1; i < j; i, j = i+1, j-1 {
			order[i], order[j] = order[j], order[i]
		}
	case "sni_last":
		if hostStart < 0 || hostEnd <= hostStart {
			return nil, fmt.Errorf("desync: sni_last requires a parsed hostname")
		}
		sort.SliceStable(order, func(i, j int) bool {
			a, b := order[i], order[j]
			aHost := bounds[a] < hostEnd && bounds[a+1] > hostStart
			bHost := bounds[b] < hostEnd && bounds[b+1] > hostStart
			return !aHost && bHost
		})
	default:
		parts := strings.Split(spec, ",")
		if len(parts) != n {
			return nil, fmt.Errorf("desync: segment order has %d entries for %d segments", len(parts), n)
		}
		seen := make([]bool, n)
		for i, p := range parts {
			v, err := strconv.Atoi(p)
			if err != nil || v < 1 || v > n || seen[v-1] {
				return nil, fmt.Errorf("desync: invalid segment permutation %q", spec)
			}
			seen[v-1], order[i] = true, v-1
		}
	}
	return order, nil
}

func flightHostname(b []byte) (hostPositions, error) {
	if initialTLSRecord(b) {
		v, ok, err := clientHello(b)
		if err != nil {
			return hostPositions{}, err
		}
		if !ok {
			return hostPositions{}, fmt.Errorf("desync: incomplete ClientHello")
		}
		return tlsPositions(v)
	}
	return httpPositions(b)
}

// hostDecoy keeps every wire offset and length unchanged. Its caller must force
// an invalid checksum when sending at the real sequence range.
func hostDecoy(b []byte, name string) ([]byte, error) {
	out := append([]byte(nil), b...)
	if initialTLSRecord(b) {
		v, complete, err := clientHello(b)
		if err != nil {
			return nil, err
		}
		if !complete {
			return nil, fmt.Errorf("desync: incomplete host decoy source")
		}
		hp, err := tlsPositions(helloView{handshake: v.handshake, wire: identity(len(v.handshake))})
		if err != nil {
			return nil, err
		}
		value := fittedHostname(name, hp.end-hp.start)
		for i, c := range value {
			out[v.wire[hp.start+i]] = c
		}
		// Do not copy subsequent handshake/application records into a decoy.
		return out[:v.wire[len(v.wire)-1]+1], nil
	}
	hp, err := httpPositions(b)
	if err != nil {
		return nil, err
	}
	copy(out[hp.start:hp.end], fittedHostname(name, hp.end-hp.start))
	end := bytes.Index(out, []byte("\r\n\r\n"))
	if end < 0 {
		return nil, fmt.Errorf("desync: incomplete HTTP host decoy source")
	}
	return out[:end+4], nil
}

func fittedHostname(name string, n int) []byte {
	if name == "" {
		name = "www.example.com"
	}
	if len(name) >= n {
		return []byte(name[len(name)-n:])
	}
	if n == len(name)+1 {
		return []byte("a" + name)
	}
	return []byte(strings.Repeat("a", n-len(name)-1) + "." + name)
}
