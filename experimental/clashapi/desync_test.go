package clashapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	outboundAdapter "github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/protocol/desync"
	"github.com/sagernet/sing/service"
)

type diagnosticDesyncOutbound struct {
	*linkAPIOutbound
	clears   int
	snapshot *desync.Snapshot
}

func (o *diagnosticDesyncOutbound) DesyncStats() desync.Snapshot {
	if o.snapshot != nil {
		return *o.snapshot
	}
	return desync.Snapshot{Version: 1, Current: "split", Reason: "test", Partition: "p", Entries: map[string]*desync.Entry{}}
}

func TestDesyncDiagnosticsRemainUsableWithFullLearningCache(t *testing.T) {
	snapshot := desync.Snapshot{Version: 1, Entries: make(map[string]*desync.Entry)}
	now := time.Now()
	for index := 0; index < 16384; index++ {
		snapshot.Entries[fmt.Sprintf("host:%d.example", index)] = &desync.Entry{
			Updated:    now.Add(time.Duration(index) * time.Second),
			Strategies: map[string]desync.Score{"fake_split": {Success: 1, LastReason: strings.Repeat("network error ", 100)}},
		}
	}
	outbound := &diagnosticDesyncOutbound{
		linkAPIOutbound: &linkAPIOutbound{Adapter: outboundAdapter.NewAdapter(C.TypeDesync, "dpi", []string{"tcp", "udp"}, nil)},
		snapshot:        &snapshot,
	}
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), &linkAPIOutboundManager{outbounds: []adapter.Outbound{outbound}})
	response := httptest.NewRecorder()
	desyncRouter(ctx).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/?outbound=dpi", nil))
	if response.Code != http.StatusOK || response.Body.Len() > 64*1024 {
		t.Fatalf("diagnostics exceed rpcd budget: status=%d bytes=%d", response.Code, response.Body.Len())
	}
	var result struct {
		Outbounds map[string]desyncDiagnosticSnapshot `json:"outbounds"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	value := result.Outbounds["dpi"]
	if value.EntryCount != 16384 || !value.EntriesTruncated || len(value.Entries) == 0 || len(value.Entries) > 64 {
		t.Fatalf("incorrect bounded diagnostics: total=%d shown=%d truncated=%v", value.EntryCount, len(value.Entries), value.EntriesTruncated)
	}
	if value.Entries["host:16383.example"] == nil {
		t.Fatal("most recent destination is missing")
	}
	if len(snapshot.Entries) != 16384 {
		t.Fatal("diagnostic truncation changed persisted learning")
	}
}
func (o *diagnosticDesyncOutbound) ClearDesync() error { o.clears++; return nil }
func TestDesyncAPIAuthenticationStatsClear(t *testing.T) {
	a := &diagnosticDesyncOutbound{linkAPIOutbound: &linkAPIOutbound{Adapter: outboundAdapter.NewAdapter(C.TypeDesync, "dpi", []string{"tcp", "udp"}, nil)}}
	b := &diagnosticDesyncOutbound{linkAPIOutbound: &linkAPIOutbound{Adapter: outboundAdapter.NewAdapter(C.TypeDesync, "other", []string{"tcp", "udp"}, nil)}}
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), &linkAPIOutboundManager{outbounds: []adapter.Outbound{a, b}})
	handler := authentication("secret")(desyncRouter(ctx))
	request := httptest.NewRequest(http.MethodDelete, "/?outbound=dpi", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || a.clears != 0 {
		t.Fatal("unauthenticated clear changed state")
	}
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		request = httptest.NewRequest(method, "/?outbound=dpi", nil)
		request.Header.Set("Authorization", "Bearer secret")
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != 200 || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: %d %s", method, response.Code, response.Body)
		}
		var result struct {
			Capability string                     `json:"capability"`
			Outbounds  map[string]desync.Snapshot `json:"outbounds"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Capability != desync.Capability || len(result.Outbounds) != 1 || result.Outbounds["dpi"].Current != "split" {
			t.Fatalf("bad stats %s", response.Body)
		}
	}
	if a.clears != 1 || b.clears != 0 {
		t.Fatal("clear not isolated to selected outbound")
	}
	request = httptest.NewRequest(http.MethodGet, "/?outbound=missing", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 404 {
		t.Fatal("missing outbound did not return404")
	}
}
