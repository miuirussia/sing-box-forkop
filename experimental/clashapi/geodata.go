package clashapi

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

// downloadGeodata streams into Forkop's staging file over loopback. The core
// owns the HTTP transport, so the selected outbound and its DNS are respected.
func (s *Server) downloadGeodata(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	local, _ := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
	// Forkop normally binds the controller to its LAN address. A connection
	// from that same local address is also router-local, unlike LAN clients.
	localPeer := ip != nil && (ip.IsLoopback() || local != nil && !local.IP.IsUnspecified() && ip.Equal(local.IP))
	if !localPeer {
		http.Error(w, "local requests only", http.StatusForbidden)
		return
	}
	var request struct {
		URL    string `json:"url"`
		Detour string `json:"detour"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&request); err != nil {
		http.Error(w, "invalid download request", http.StatusBadRequest)
		return
	}
	u, err := url.Parse(request.URL)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		http.Error(w, "expected HTTP(S) URL", http.StatusBadRequest)
		return
	}
	if !s.geodataAccess.TryLock() {
		http.Error(w, "a geodata download is already running", http.StatusConflict)
		return
	}
	defer s.geodataAccess.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	// Cancelling the upstream request cannot interrupt a blocked response write.
	deadline, _ := ctx.Deadline()
	if err := http.NewResponseController(w).SetWriteDeadline(deadline); err != nil {
		http.Error(w, "cannot set download write deadline", http.StatusInternalServerError)
		return
	}
	manager := service.FromContext[adapter.HTTPClientManager](s.ctx)
	if manager == nil {
		http.Error(w, "HTTP client is unavailable", http.StatusServiceUnavailable)
		return
	}
	transport, err := manager.ResolveTransport(ctx, log.StdLogger(), option.HTTPClientOptions{
		DialerOptions: option.DialerOptions{Detour: request.Detour}, DisableEmptyDirectCheck: true,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	upstream, err := http.NewRequestWithContext(ctx, http.MethodGet, request.URL, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	response, err := client.Do(upstream)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	const maxSize = 128 << 20
	if response.StatusCode != http.StatusOK || response.ContentLength > maxSize {
		http.Error(w, "download refused: HTTP status or size limit", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	// Forkop independently enforces the same byte cap and validates protobuf
	// framing before publishing; a broken or oversized stream never replaces it.
	n, err := io.CopyBuffer(w, io.LimitReader(response.Body, maxSize+1), make([]byte, 32*1024))
	if err == nil && n > 0 && n <= maxSize {
		// The receiver retains just this trailer. Without it, even an HTTP
		// stream cut exactly at a protobuf entry boundary is rejected.
		_, _ = io.WriteString(w, "\nFORKOP-GEODATA-DONE\n")
	}
}
