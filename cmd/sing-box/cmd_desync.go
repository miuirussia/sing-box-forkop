package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	box "github.com/sagernet/sing-box"
	engine "github.com/sagernet/sing-box/common/desync"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	desync "github.com/sagernet/sing-box/protocol/desync"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/spf13/cobra"
)

func init() { mainCommand.AddCommand(newDesyncCommand()) }
func writeDesyncJSON(cmd *cobra.Command, value any) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}
func readDesyncInput(cmd *cobra.Command, args []string) (string, error) {
	if len(args) > 0 {
		return args[0], nil
	}
	data, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), 131073))
	if len(data) > 131072 {
		return "", fmt.Errorf("input exceeds 128 KiB")
	}
	return string(data), err
}
func decodeDesyncInput(input string) (option.DesyncOptions, error) {
	if strings.HasPrefix(strings.TrimSpace(input), "{") {
		var o option.DesyncOptions
		err := json.Unmarshal([]byte(input), &o)
		return o, err
	}
	return option.ParseDesyncStrategy(input)
}
func newDesyncCommand() *cobra.Command {
	root := &cobra.Command{Use: "desync", Short: "Validate, convert and probe Forkop desync strategies", SilenceUsage: true}
	root.AddCommand(&cobra.Command{Use: "capabilities", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		capabilities := desync.Capabilities()
		capabilities["protocols"] = desyncProbeProtocols()
		capabilities["limits"] = map[string]any{"max_bytes": 1048576, "timeout": "1s..15s", "attempts": 1}
		return writeDesyncJSON(cmd, capabilities)
	}})
	for _, verb := range []string{"import", "export", "check"} {
		root.AddCommand(&cobra.Command{Use: verb + " [strategy-or-json]", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			input, err := readDesyncInput(cmd, args)
			if err != nil {
				return err
			}
			o, err := decodeDesyncInput(input)
			if err != nil {
				return err
			}
			if verb == "import" {
				return writeDesyncJSON(cmd, o)
			}
			o, err = option.NormalizeDesyncOptions(o)
			if err != nil {
				return err
			}
			if verb == "check" {
				if err = engine.Validate(o); err != nil {
					return err
				}
			}
			if verb == "export" {
				s, err := option.ExportDesyncStrategy(o)
				if err == nil {
					_, err = fmt.Fprintln(cmd.OutOrStdout(), s)
				}
				return err
			}
			return writeDesyncJSON(cmd, o)
		}})
	}
	root.AddCommand(newDesyncProbeCommand())
	return root
}

type desyncProbeResult struct {
	Success       bool                 `json:"success"`
	Protocol      string               `json:"protocol"`
	Target        string               `json:"target"`
	Options       option.DesyncOptions `json:"options"`
	LatencyMS     float64              `json:"latency_ms"`
	DurationMS    float64              `json:"duration_ms"`
	Bytes         int64                `json:"bytes"`
	ThroughputBPS float64              `json:"throughput_bps,omitempty"`
	Status        int                  `json:"status,omitempty"`
	TLSVersion    uint16               `json:"tls_version,omitempty"`
	Error         string               `json:"error,omitempty"`
}

func newDesyncProbeCommand() *cobra.Command {
	var filename, target, protocol, output, sni, strategy, iface string
	var dnsServers []string
	var mark uint32
	var timeout time.Duration
	var maxBytes int64
	cmd := &cobra.Command{Use: "probe", Aliases: []string{"test"}, Short: "One bounded probe through an isolated desync outbound", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if timeout < time.Second || timeout > 15*time.Second || maxBytes < 1024 || maxBytes > 1048576 {
			return fmt.Errorf("timeout must be 1s..15s and max-bytes 1024..1048576")
		}
		if filename != "" && strategy != "" {
			return fmt.Errorf("use either --options or --strategy")
		}
		var o option.DesyncOptions
		var err error
		if filename != "" {
			f, e := os.Open(filename)
			if e != nil {
				return e
			}
			data, e := io.ReadAll(io.LimitReader(f, 131073))
			f.Close()
			if e != nil {
				return e
			}
			if len(data) > 131072 {
				return fmt.Errorf("options exceeds 128 KiB")
			}
			err = json.Unmarshal(data, &o)
		} else {
			o, err = decodeDesyncInput(strategy)
		}
		if err != nil {
			return err
		}
		if cmd.Flags().Changed("interface") {
			o.BindInterface = iface
		}
		if cmd.Flags().Changed("routing-mark") {
			o.RoutingMark = option.FwMark(mark)
		}
		off := false
		o.AutoTune = &off
		o.Adaptive = nil
		o, err = option.NormalizeDesyncOptions(o)
		if err != nil {
			return err
		}
		if err = engine.Validate(o); err != nil {
			return err
		}
		if !desyncProtocolAvailable(protocol) {
			return fmt.Errorf("desync: protocol %q unavailable; QUIC requires with_quic build", protocol)
		}
		signalCtx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ctx, cancel := context.WithTimeout(signalCtx, timeout)
		defer cancel()
		result := runDesyncProbe(ctx, o, target, protocol, sni, maxBytes, dnsServers)
		if output != "" {
			data, e := json.Marshal(result)
			if e != nil {
				return e
			}
			if e = os.WriteFile(output, append(data, '\n'), 0600); e != nil {
				return e
			}
		}
		return writeDesyncJSON(cmd, result)
	}}
	f := cmd.Flags()
	f.StringVar(&filename, "options", "", "strategy JSON file")
	f.StringVar(&strategy, "strategy", "", "key=value strategy")
	f.StringVar(&target, "target", "", "host:port, or HTTP(S) URL")
	f.StringVar(&protocol, "protocol", "tls", "tls, http, or quic")
	f.Uint32Var(&mark, "routing-mark", 0, "bypass routing mark")
	f.DurationVar(&timeout, "timeout", 10*time.Second, "total probe deadline")
	f.Int64Var(&maxBytes, "max-bytes", 65536, "maximum response body bytes")
	f.StringVar(&output, "output", "", "write result JSON to file")
	f.StringVar(&sni, "sni", "", "TLS server name override")
	f.StringVar(&iface, "interface", "", "bind probe and DNS sockets to interface")
	f.StringArrayVar(&dnsServers, "dns-server", nil, "direct DNS URI (repeatable; default udp://1.1.1.1)")
	_ = cmd.MarkFlagRequired("target")
	return cmd
}
func runDesyncProbe(ctx context.Context, o option.DesyncOptions, target, protocol, sni string, maxBytes int64, dnsServers []string) desyncProbeResult {
	result := desyncProbeResult{Options: o, Target: target, Protocol: protocol}
	start := time.Now()
	finish := func(err error) desyncProbeResult {
		result.DurationMS = float64(time.Since(start).Microseconds()) / 1000
		result.Success = err == nil
		if err != nil {
			result.Error = err.Error()
		}
		return result
	}
	// A fresh Box uses the production resolver, interface, mark and IPv6 dialer;
	// no active instance, cache file, or routing configuration is changed.
	dnsOptions, dnsErr := desyncProbeDNS(dnsServers, o)
	if dnsErr != nil {
		return finish(dnsErr)
	}
	config := option.Options{Log: &option.LogOptions{Disabled: true}, DNS: dnsOptions, Route: &option.RouteOptions{DefaultDomainResolver: &option.DomainResolveOptions{Server: "probe-dns"}}}
	o.DomainResolver = &option.DomainResolveOptions{Server: "probe-dns"}
	config.Outbounds = []option.Outbound{{Type: C.TypeDesync, Tag: "desync-probe", Options: &o}}
	instance, err := box.New(box.Options{Options: config, Context: globalCtx})
	if err != nil {
		return finish(err)
	}
	defer instance.Close()
	if err = instance.Start(); err != nil {
		return finish(err)
	}
	out, _ := instance.Outbound().Outbound("desync-probe")
	hostport := target
	if protocol == "http" {
		u, e := url.Parse(target)
		if e != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return finish(fmt.Errorf("http target must be an http(s) URL"))
		}
		hostport = u.Host
		if u.Port() == "" {
			port := "80"
			if u.Scheme == "https" {
				port = "443"
			}
			hostport = net.JoinHostPort(u.Hostname(), port)
		}
	}
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return finish(err)
	}
	if sni == "" {
		sni = host
	}
	switch protocol {
	case "tls":
		conn, e := out.DialContext(ctx, "tcp", M.ParseSocksaddr(hostport))
		if e != nil {
			return finish(e)
		}
		defer conn.Close()
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		tc := tls.Client(conn, &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12})
		if e = tc.HandshakeContext(ctx); e != nil {
			return finish(e)
		}
		result.LatencyMS = float64(time.Since(start).Microseconds()) / 1000
		result.TLSVersion = tc.ConnectionState().Version
	case "http":
		transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return out.DialContext(ctx, network, M.ParseSocksaddr(address))
		}, TLSClientConfig: &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true, MaxResponseHeaderBytes: 32768}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		request, e := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if e != nil {
			return finish(e)
		}
		response, e := client.Do(request)
		if e != nil {
			return finish(e)
		}
		defer response.Body.Close()
		result.Status = response.StatusCode
		result.LatencyMS = float64(time.Since(start).Microseconds()) / 1000
		bodyStart := time.Now()
		result.Bytes, e = io.Copy(io.Discard, io.LimitReader(response.Body, maxBytes))
		if e != nil {
			return finish(e)
		}
		elapsed := time.Since(bodyStart).Seconds()
		if result.Bytes > 0 && elapsed > 0 {
			result.ThroughputBPS = float64(result.Bytes) / elapsed
		}
		if response.StatusCode < 200 || response.StatusCode >= 400 {
			return finish(fmt.Errorf("HTTP status %d", response.StatusCode))
		}
	case "quic":
		err = probeDesyncQUIC(ctx, out, hostport, sni, &result)
		if err != nil {
			return finish(err)
		}
	default:
		return finish(fmt.Errorf("unknown probe protocol"))
	}
	return finish(nil)
}
