//go:build with_quic

package main

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

func desyncProbeProtocols() []string        { return []string{"tls", "http", "quic"} }
func desyncProtocolAvailable(p string) bool { return p == "tls" || p == "http" || p == "quic" }
func probeDesyncQUIC(ctx context.Context, out adapter.Outbound, target, sni string, result *desyncProbeResult) error {
	start := time.Now()
	conn, err := out.DialContext(ctx, "udp", M.ParseSocksaddr(target))
	if err != nil {
		return err
	}
	defer conn.Close()
	qc, err := quic.DialEarlyConn(ctx, conn, &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}}, &quic.Config{HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 5 * time.Second})
	if err != nil {
		return err
	}
	defer qc.CloseWithError(0, "")
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-qc.Context().Done():
		return context.Cause(qc.Context())
	case <-qc.HandshakeComplete():
		result.LatencyMS = float64(time.Since(start).Microseconds()) / 1000
		result.TLSVersion = qc.ConnectionState().TLS.Version
		return nil
	}
}
