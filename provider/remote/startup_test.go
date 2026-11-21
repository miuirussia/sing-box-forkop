package provider_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

// Like a tunnel, this outbound uses its detour as soon as Start is called.
type startupProbe struct {
	outbound.Adapter
	adapter.Outbound
	manager adapter.OutboundManager
	detour  string
}

func (p *startupProbe) Type() string           { return p.Adapter.Type() }
func (p *startupProbe) Tag() string            { return p.Adapter.Tag() }
func (p *startupProbe) Network() []string      { return p.Adapter.Network() }
func (p *startupProbe) Dependencies() []string { return p.Adapter.Dependencies() }
func (p *startupProbe) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	group, _ := p.manager.Outbound(p.detour)
	if group.(adapter.OutboundGroup).Selected("tcp") == nil {
		return fmt.Errorf("missing supported outbound at tunnel start")
	}
	return nil
}

func startupInstance(t *testing.T, config string) (*box.Box, context.Context) {
	t.Helper()
	ctx := include.Context(context.Background())
	registry := service.FromContext[adapter.OutboundRegistry](ctx).(*outbound.Registry)
	outbound.Register[option.DialerOptions](registry, "startup-probe", func(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options option.DialerOptions) (adapter.Outbound, error) {
		return &startupProbe{Adapter: outbound.NewAdapterWithDialerOptions("startup-probe", tag, []string{"tcp", "udp"}, options), manager: service.FromContext[adapter.OutboundManager](ctx), detour: options.Detour}, nil
	})
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(config))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	return instance, ctx
}

func TestSubscriptionLoadedBeforeDependentTunnelStarts(t *testing.T) {
	for _, group := range []string{
		`{"type":"selector","tag":"proxy","providers":["sub"]}`,
		`{"type":"urltest","tag":"proxy","providers":["sub"]}`,
		`{"type":"fallback","tag":"proxy","providers":["sub"]}`,
		`{"type":"selector","tag":"proxy","use_all_providers":true}`,
	} {
		t.Run(group, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				fmt.Fprint(w, `{"outbounds":[{"type":"http","tag":"node","server":"127.0.0.1","server_port":8080}]}`)
			}))
			defer server.Close()
			source := server.URL
			// Exercise the encrypted source used by the router as well as plain HTTP.
			if strings.Contains(group, `"urltest"`) {
				source = incyStartupURL(t, source)
			}
			config := `{
				"log":{"disabled":true},
				"providers":[{"type":"remote","tag":"sub","url":` + strconv.Quote(source) + `}],
				"outbounds":[
					{"type":"direct","tag":"direct"},` + group + `,
					{"type":"startup-probe","tag":"tunnel","detour":"proxy"}
				]
			}`
			instance, _ := startupInstance(t, config)
			if err := instance.Start(); err != nil {
				t.Fatal(err)
			}
			if requests.Load() != 1 {
				t.Fatalf("initial requests = %d, want 1", requests.Load())
			}
		})
	}
}

func incyStartupURL(t *testing.T, target string) string {
	t.Helper()
	key, err := base64.StdEncoding.DecodeString("9tQOoMioiZ18aC0Jug1BZd/is91F5rs+JcsjPPAMJGI=")
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	payload := `{"v":1,"url":` + strconv.Quote(target) + `}`
	return "incy://crypt1/" + base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(payload), nil))
}

func TestSubscriptionDownloadsThroughAnotherProviderBeforeTunnelStarts(t *testing.T) {
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != "subscription.invalid:80" {
			t.Errorf("unexpected proxy request: %s", r.URL)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		conn, stream, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		fmt.Fprint(stream, "HTTP/1.1 200 Connection Established\r\n\r\n")
		stream.Flush()
		if _, err := http.ReadRequest(stream.Reader); err != nil {
			t.Error(err)
			return
		}
		proxied.Add(1)
		body := `{"outbounds":[{"type":"http","tag":"node","server":"127.0.0.1","server_port":8080}]}`
		fmt.Fprintf(stream, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		stream.Flush()
	}))
	defer proxy.Close()
	address, _ := url.Parse(proxy.URL)
	host, port, _ := net.SplitHostPort(address.Host)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"outbounds":[{"type":"http","tag":"relay","server":%q,"server_port":%s}]}`, host, port)
	}))
	defer server.Close()
	instance, _ := startupInstance(t, `{
		"log":{"disabled":true},
		"providers":[
			{"type":"remote","tag":"second","url":"http://subscription.invalid/sub","download_detour":"relay"},
			{"type":"remote","tag":"first","url":`+strconv.Quote(server.URL)+`}
		],
		"outbounds":[
			{"type":"direct","tag":"direct"},
			{"type":"startup-probe","tag":"tunnel","detour":"proxy"},
			{"type":"selector","tag":"proxy","providers":["second"]},
			{"type":"selector","tag":"relay","providers":["first"]}
		]
	}`)
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	if proxied.Load() != 1 {
		t.Fatalf("proxied subscription requests = %d, want 1", proxied.Load())
	}
}

func TestCachedSubscriptionStartsWithoutNetwork(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, `{"outbounds":[{"type":"http","tag":"node","server":"127.0.0.1","server_port":8080}]}`)
	}))
	defer server.Close()
	config := `{
		"log":{"disabled":true},
		"experimental":{"cache_file":{"enabled":true,"store_subscriptions":true,"path":` + strconv.Quote(filepath.Join(t.TempDir(), "cache.db")) + `}},
		"providers":[{"type":"remote","tag":"sub","url":` + strconv.Quote(server.URL) + `}],
		"outbounds":[
			{"type":"direct","tag":"direct"},
			{"type":"selector","tag":"proxy","providers":["sub"]},
			{"type":"startup-probe","tag":"tunnel","detour":"proxy"}
		]
	}`
	first, _ := startupInstance(t, config)
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	server.Close()
	second, _ := startupInstance(t, config)
	if err := second.Start(); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatalf("requests = %d, want only the first download", requests.Load())
	}
}

func TestSubscriptionDownloadCycleIsReported(t *testing.T) {
	instance, _ := startupInstance(t, `{
		"log":{"disabled":true},
		"providers":[{"type":"remote","tag":"sub","url":"http://subscription.invalid/sub","download_detour":"proxy"}],
		"outbounds":[{"type":"direct","tag":"direct"},{"type":"selector","tag":"proxy","providers":["sub"]}]
	}`)
	if err := instance.Start(); err == nil || !strings.Contains(err.Error(), "circular outbound/provider dependency") {
		t.Fatalf("expected a dependency cycle, got %v", err)
	}
}

func TestInitialSubscriptionFailureDoesNotStartAnEmptyTunnel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer server.Close()
	instance, _ := startupInstance(t, `{
		"log":{"disabled":true},
		"providers":[{"type":"remote","tag":"sub","url":`+strconv.Quote(server.URL)+`}],
		"outbounds":[{"type":"direct","tag":"direct"},{"type":"selector","tag":"proxy","providers":["sub"]},{"type":"startup-probe","tag":"tunnel","detour":"proxy"}]
	}`)
	if err := instance.Start(); err == nil || !strings.Contains(err.Error(), "load initial outbound provider sub") {
		t.Fatalf("expected the initial download failure, got %v", err)
	}
}

func TestSubscriptionDownloadsThroughGroupWithStaticBootstrap(t *testing.T) {
	for _, groupType := range []string{"selector", "urltest", "fallback"} {
		t.Run(groupType, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				requests.Add(1)
				fmt.Fprint(w, `{"outbounds":[{"type":"http","tag":"node","server":"127.0.0.1","server_port":8080}]}`)
			}))
			defer server.Close()
			group := `{"type":` + strconv.Quote(groupType) + `,"tag":"proxy","outbounds":["direct"],"providers":["sub"]`
			if groupType != "selector" {
				group += `,"url":` + strconv.Quote(server.URL+"/health")
			}
			group += `}`
			instance, ctx := startupInstance(t, `{
				"log":{"disabled":true},
				"route":{"final":"proxy"},
				"providers":[{"type":"remote","tag":"sub","url":`+strconv.Quote(server.URL)+`}],
				"outbounds":[{"type":"direct","tag":"direct"},`+group+`,{"type":"startup-probe","tag":"tunnel","detour":"proxy"}]
			}`)
			if err := instance.Start(); err != nil {
				t.Fatal(err)
			}
			outbound, _ := service.FromContext[adapter.OutboundManager](ctx).Outbound("proxy")
			if members := outbound.(adapter.OutboundGroup).All(); len(members) != 2 {
				t.Fatalf("group members = %v, want direct and sub/node", members)
			}
			if requests.Load() != 1 {
				t.Fatalf("subscription requests = %d, want 1", requests.Load())
			}
		})
	}
}

func TestInitialSubscriptionFetchHonorsDNSRules(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"outbounds":[{"type":"http","tag":"node","server":"127.0.0.1","server_port":8080}]}`)
	}))
	defer server.Close()
	address, _ := url.Parse(server.URL)
	_, port, _ := net.SplitHostPort(address.Host)
	instance, _ := startupInstance(t, `{
		"log":{"disabled":true},
		"dns":{
		    "servers":[{"type":"hosts","tag":"empty","predefined":{}},{"type":"hosts","tag":"bootstrap","predefined":{"sub.test":["127.0.0.1"]}}],
		    "rules":[{"domain":"sub.test","action":"route","server":"bootstrap"}],"final":"empty"
		},
		"providers":[{"type":"remote","tag":"sub","url":"http://sub.test:`+port+`/sub"}],
		"outbounds":[{"type":"direct","tag":"direct"},{"type":"selector","tag":"proxy","providers":["sub"]}]
	}`)
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
}

func TestCachedSubscriptionStartsThroughOwnGroup(t *testing.T) {
	for _, groupType := range []string{"selector", "urltest", "fallback"} {
		t.Run(groupType, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				fmt.Fprint(w, `{"outbounds":[{"type":"http","tag":"node","server":"127.0.0.1","server_port":8080}]}`)
			}))
			defer server.Close()
			config := `{
				"log":{"disabled":true},
				"experimental":{"cache_file":{"enabled":true,"store_subscriptions":true,"path":` + strconv.Quote(filepath.Join(t.TempDir(), "cache.db")) + `}},
				"providers":[{"type":"remote","tag":"sub","url":` + strconv.Quote(server.URL) + `,"download_detour":"direct"}],
				"outbounds":[{"type":"direct","tag":"direct"},{"type":` + strconv.Quote(groupType) + `,"tag":"proxy","providers":["sub"]},{"type":"startup-probe","tag":"tunnel","detour":"proxy"}]
			}`
			first, _ := startupInstance(t, config)
			if err := first.Start(); err != nil {
				t.Fatal(err)
			}
			if err := first.Close(); err != nil {
				t.Fatal(err)
			}
			server.Close()
			config = strings.ReplaceAll(config, `"download_detour":"direct"`, `"download_detour":"proxy"`)
			second, _ := startupInstance(t, config)
			if err := second.Start(); err != nil {
				t.Fatal(err)
			}
			if requests.Load() != 1 {
				t.Fatalf("subscription requests = %d, want only the initial fetch", requests.Load())
			}
		})
	}
}

func TestStartupLoadsRemoteDNSRuleSetMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"version":3,"rules":[{"ip_cidr":["192.0.2.0/24"]}]}`)
	}))
	defer server.Close()
	instance, ctx := startupInstance(t, `{
		"log":{"disabled":true},
		"dns":{"servers":[{"type":"hosts","tag":"hosts"}],"rules":[{"rule_set":"subnets","server":"hosts"}]},
		"route":{"rule_set":[{"type":"remote","tag":"subnets","format":"source","url":`+strconv.Quote(server.URL)+`,"download_detour":"direct"}]},
		"outbounds":[{"type":"direct","tag":"direct"}]
	}`)
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	ruleSet, loaded := service.FromContext[adapter.Router](ctx).RuleSet("subnets")
	if !loaded || !ruleSet.Metadata().ContainsIPCIDRRule {
		t.Fatal("remote DNS rule-set did not load its IP metadata")
	}
}
