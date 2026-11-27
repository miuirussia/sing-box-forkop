//go:build !with_quic

package main

import (
	"context"
	"fmt"
	"github.com/sagernet/sing-box/adapter"
)

func desyncProbeProtocols() []string        { return []string{"tls", "http"} }
func desyncProtocolAvailable(p string) bool { return p == "tls" || p == "http" }
func probeDesyncQUIC(context.Context, adapter.Outbound, string, string, *desyncProbeResult) error {
	return fmt.Errorf("QUIC probe requires with_quic build")
}
