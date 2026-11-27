package clashapi

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/protocol/desync"
	"github.com/sagernet/sing/service"
)

type desyncDiagnosticSnapshot struct {
	desync.Snapshot
	EntryCount       int  `json:"entry_count"`
	EntriesTruncated bool `json:"entries_truncated"`
}

// rpcd transports the diagnostics to LuCI with a response-size limit. Keep
// persistence snapshots complete and bound only the diagnostic representation.
func boundedDesyncSnapshot(snapshot desync.Snapshot, budget int) (desyncDiagnosticSnapshot, int) {
	entries := snapshot.Entries
	snapshot.Entries = make(map[string]*desync.Entry)
	if len(snapshot.Reason) > 1024 {
		snapshot.Reason = snapshot.Reason[:1024]
	}
	result := desyncDiagnosticSnapshot{Snapshot: snapshot, EntryCount: len(entries), EntriesTruncated: len(entries) > 0}
	base, _ := json.Marshal(result)
	used := len(base)
	if used >= budget {
		return result, used
	}
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := entries[keys[i]], entries[keys[j]]
		if a == nil || b == nil {
			if a == nil && b == nil {
				return keys[i] < keys[j]
			}
			return b == nil
		}
		if a.Updated.Equal(b.Updated) {
			return keys[i] < keys[j]
		}
		return a.Updated.After(b.Updated)
	})
	for _, key := range keys {
		if len(result.Entries) >= 64 {
			break
		}
		encodedKey, _ := json.Marshal(key)
		encodedEntry, err := json.Marshal(entries[key])
		cost := len(encodedKey) + len(encodedEntry) + 2
		if err != nil || used+cost > budget {
			continue
		}
		result.Entries[key] = entries[key]
		used += cost
	}
	result.EntriesTruncated = len(result.Entries) < result.EntryCount
	return result, used
}

func desyncRouter(ctx context.Context) http.Handler {
	r := chi.NewRouter()
	handler := func(w http.ResponseWriter, r *http.Request) {
		manager := service.FromContext[adapter.OutboundManager](ctx)
		result := map[string]desyncDiagnosticSnapshot{}
		tag := r.URL.Query().Get("outbound")
		found := false
		outboundCount := 0
		remaining := 60 * 1024
		for _, out := range manager.Outbounds() {
			if tag != "" && out.Tag() != tag {
				continue
			}
			d, ok := out.(interface {
				DesyncStats() desync.Snapshot
				ClearDesync() error
			})
			if !ok {
				continue
			}
			found = true
			outboundCount++
			if r.Method == http.MethodDelete {
				if err := d.ClearDesync(); err != nil {
					render.Status(r, http.StatusInternalServerError)
					render.JSON(w, r, newError(err.Error()))
					return
				}
			}
			if outboundCount > 32 {
				continue
			}
			encodedTag, _ := json.Marshal(out.Tag())
			bounded, size := boundedDesyncSnapshot(d.DesyncStats(), remaining-len(encodedTag)-2)
			if size+len(encodedTag)+2 <= remaining {
				result[out.Tag()] = bounded
				remaining -= size + len(encodedTag) + 2
			}
		}
		if tag != "" && !found {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, newError("desync outbound not found"))
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		render.JSON(w, r, render.M{"capability": desync.Capability, "outbounds": result, "outbound_count": outboundCount, "outbounds_truncated": len(result) < outboundCount})
	}
	r.Get("/", handler)
	r.Delete("/", handler)
	return r
}
