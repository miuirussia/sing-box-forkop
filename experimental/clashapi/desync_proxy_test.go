package clashapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	outboundAdapter "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
)

func TestDesyncProxyAPIReportsType(t *testing.T) {
	t.Parallel()

	outbound := &linkAPIOutbound{
		Adapter: outboundAdapter.NewAdapter(
			C.TypeDesync,
			"dpi",
			[]string{"tcp", "udp"},
			nil,
		),
	}
	server := &Server{
		outbound:       &linkAPIOutboundManager{outbounds: []adapter.Outbound{outbound}},
		endpoint:       &linkAPIEndpointManager{},
		urlTestHistory: urltest.NewHistoryStorage(),
	}
	handler := proxyRouter(server, nil)
	for _, test := range []struct {
		name string
		path string
	}{
		{name: "proxy list", path: "/"},
		{name: "individual proxy", path: "/dpi"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
			if response.Code != http.StatusOK {
				t.Fatalf("status %d: %s", response.Code, response.Body)
			}
			value := make(map[string]json.RawMessage)
			if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
				t.Fatalf("decode proxy response: %v", err)
			}
			if test.path == "/" {
				proxies := make(map[string]map[string]json.RawMessage)
				if err := json.Unmarshal(value["proxies"], &proxies); err != nil {
					t.Fatalf("decode proxy list: %v", err)
				}
				value = proxies["dpi"]
			}
			if string(value["type"]) != `"Desync"` {
				t.Errorf("type = %s, want Desync", value["type"])
			}
			if string(value["name"]) != `"dpi"` || string(value["udp"]) != "true" {
				t.Errorf("unexpected outbound metadata: %s", response.Body)
			}
		})
	}
}
