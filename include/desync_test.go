package include

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/desync"
	SJSON "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
)

func TestDesyncProductionCacheRestored(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer server.Close()
	cachePath, _ := json.Marshal(filepath.Join(t.TempDir(), "cache.db"))
	open := func() *box.Box {
		t.Helper()
		ctx := Context(context.Background())
		var opts option.Options
		config := fmt.Sprintf(`{"log":{"disabled":true},"experimental":{"cache_file":{"enabled":true,"path":%s}},"outbounds":[{"type":"desync","tag":"dpi","preset":"auto","mode":"none"}]}`, cachePath)
		if err := SJSON.UnmarshalContext(ctx, []byte(config), &opts); err != nil {
			t.Fatal(err)
		}
		instance, err := box.New(box.Options{Options: opts, Context: ctx})
		if err != nil {
			t.Fatal(err)
		}
		if err = instance.Start(); err != nil {
			instance.Close()
			t.Fatal(err)
		}
		return instance
	}
	first := open()
	first.Network().ResetNetwork(context.Background())
	out, _ := first.Outbound().Outbound("dpi")
	conn, err := out.DialContext(context.Background(), "tcp", M.ParseSocksaddr(server.Listener.Addr().String()))
	if err != nil {
		first.Close()
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	if err != nil {
		conn.Close()
		first.Close()
		t.Fatal(err)
	}
	_, err = io.ReadAll(conn)
	_ = conn.Close()
	if err != nil {
		first.Close()
		t.Fatal(err)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	second := open()
	defer second.Close()
	out, _ = second.Outbound().Outbound("dpi")
	stats := out.(interface{ DesyncStats() desync.Snapshot }).DesyncStats()
	if len(stats.Entries) == 0 {
		t.Fatal("cache.db not restored by real outbound lifecycle")
	}
	if stats.RouteGeneration != 1 {
		t.Fatalf("updated route epoch not restored by real outbound lifecycle: %d", stats.RouteGeneration)
	}
	if err = out.(interface{ ClearDesync() error }).ClearDesync(); err != nil {
		t.Fatal(err)
	}
	if len(out.(interface{ DesyncStats() desync.Snapshot }).DesyncStats().Entries) != 0 {
		t.Fatal("active clear retained memory")
	}
}
