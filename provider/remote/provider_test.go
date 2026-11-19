package provider

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func TestNextProviderUpdateInterval(t *testing.T) {
	updateErr := errors.New("fetch failed")
	for _, testCase := range []struct {
		name     string
		interval time.Duration
		err      error
		expected time.Duration
	}{
		{"success", 6 * time.Hour, nil, 6 * time.Hour},
		{"failed", 6 * time.Hour, updateErr, time.Minute},
		{"failed short interval", 30 * time.Second, updateErr, 30 * time.Second},
		{"disabled", 0, nil, 0},
		{"disabled failed", 0, updateErr, time.Minute},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			remote := &ProviderRemote{updateInterval: testCase.interval}
			if actual := remote.nextUpdateInterval(testCase.err); actual != testCase.expected {
				t.Fatalf("unexpected interval: %s", actual)
			}
		})
	}
}

// A provider that keeps failing backs off to its configured interval: an expired account fails
// identically forever.
func TestProviderRetriesBackOffToTheConfiguredInterval(t *testing.T) {
	updateErr := errors.New("fetch failed")
	for _, testCase := range []struct {
		name     string
		interval time.Duration
		expected []time.Duration
	}{
		{
			"hourly",
			time.Hour,
			[]time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 32 * time.Minute, time.Hour, time.Hour},
		},
		{
			// Without a configured interval there is nothing to back off
			// towards, so the retries settle at the ceiling instead.
			"disabled",
			0,
			[]time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 32 * time.Minute, time.Hour, time.Hour},
		},
		{
			// An interval below the first retry is never overshot.
			"shorter than the first retry",
			30 * time.Second,
			[]time.Duration{30 * time.Second, 30 * time.Second},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			remote := &ProviderRemote{updateInterval: testCase.interval}
			for attempt, expected := range testCase.expected {
				if actual := remote.nextUpdateInterval(updateErr); actual != expected {
					t.Fatalf("failure %d was retried after %s, expected %s", attempt+1, actual, expected)
				}
			}
			// One success puts the provider back on its normal schedule.
			if actual := remote.nextUpdateInterval(nil); actual != testCase.interval {
				t.Fatalf("a recovered provider was rescheduled after %s, expected %s", actual, testCase.interval)
			}
			if actual := remote.nextUpdateInterval(updateErr); actual != testCase.expected[0] {
				t.Fatalf("the first failure after a success was retried after %s, expected %s", actual, testCase.expected[0])
			}
		})
	}
}

func TestFetchProviderHonorsDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-request.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	remote := &ProviderRemote{url: server.URL, headers: http.Header{"User-Agent": []string{"sing-box"}}}
	if _, err := remote.fetchProvider(ctx, server.Client()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled provider response was not canceled: %v", err)
	}
}

func TestProviderRequestUserAgentHeaderOverridesTheOption(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		userAgent  string
		configured badoption.HTTPHeader
		expected   string
		encrypted  bool
	}{
		{name: "default", expected: "sing-box " + C.Version},
		{name: "option", userAgent: "Clash", expected: "Clash"},
		{name: "header", configured: badoption.HTTPHeader{"User-Agent": {"Happ"}}, expected: "Happ"},
		{name: "lower case header", userAgent: "Clash", configured: badoption.HTTPHeader{"user-agent": {"Happ"}}, expected: "Happ"},
		{name: "removed", configured: badoption.HTTPHeader{"User-Agent": {""}}},
		{
			name:       "encrypted provider keeps the header",
			configured: badoption.HTTPHeader{"User-Agent": {"custom"}},
			expected:   "custom",
			encrypted:  true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			received := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				received <- request.Header.Get("User-Agent")
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()
			source := server.URL
			if testCase.encrypted {
				source = incyProviderTestLink(t, source)
			}

			provider, err := NewProviderRemote(
				service.ContextWith[adapter.OutboundManager](context.Background(), nil),
				nil,
				log.NewNOPFactory(),
				"provider",
				option.ProviderRemoteOptions{URL: source, UserAgent: testCase.userAgent, Headers: testCase.configured},
			)
			if err != nil {
				t.Fatal(err)
			}
			remote := provider.(*ProviderRemote)
			// The response is rejected before it is parsed, so the request the
			// provider actually built is all this exercises.
			if _, err := remote.fetchProvider(context.Background(), server.Client()); err == nil {
				t.Fatal("failed provider response was accepted")
			}
			if actual := <-received; actual != testCase.expected {
				t.Fatalf("provider sent User-Agent %q, expected %q", actual, testCase.expected)
			}
		})
	}
}

func TestProviderRedirectReferer(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		encrypted   bool
		crossOrigin bool
		referer     string
	}{
		{name: "encrypted across origins", encrypted: true, crossOrigin: true},
		{name: "encrypted within one origin", encrypted: true},
		{name: "encrypted with configured referer", encrypted: true, crossOrigin: true, referer: "https://example.com/"},
		{name: "plain across origins", crossOrigin: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			received := make(chan string, 1)
			serveResult := func(w http.ResponseWriter, r *http.Request) {
				received <- r.Referer()
				w.WriteHeader(http.StatusNotModified)
			}
			location := "/result"
			if testCase.crossOrigin {
				destination := httptest.NewServer(http.HandlerFunc(serveResult))
				defer destination.Close()
				location = destination.URL + location
			}
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/result" {
					serveResult(w, r)
					return
				}
				http.Redirect(w, r, location, http.StatusFound)
			}))
			defer source.Close()
			remote := &ProviderRemote{
				ctx:          t.Context(),
				logger:       log.NewNOPFactory().NewLogger("test"),
				dialer:       systemTestDialer{},
				url:          source.URL + "/subscription?token=example",
				encryptedURL: testCase.encrypted,
				headers:      make(http.Header),
			}
			want := testCase.referer
			if testCase.referer != "" {
				remote.headers.Set("Referer", testCase.referer)
			} else if !testCase.encrypted || !testCase.crossOrigin {
				want = remote.url
			}
			if err := remote.Update(); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-received:
				if got != want {
					t.Fatalf("Referer = %q, want %q", got, want)
				}
			default:
				t.Fatal("redirect destination was not reached")
			}
		})
	}
}

func TestEncryptedProviderKeepsRedirectLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/subscription", http.StatusFound)
	}))
	defer server.Close()
	remote := &ProviderRemote{
		ctx:          t.Context(),
		logger:       log.NewNOPFactory().NewLogger("test"),
		dialer:       systemTestDialer{},
		url:          server.URL + "/subscription",
		encryptedURL: true,
	}
	if err := remote.Update(); !errors.Is(err, errProviderRedirectLimit) {
		t.Fatalf("redirect loop returned %v", err)
	}
}

func TestEncryptedProviderHidesRequestFailureDetails(t *testing.T) {
	const privateDetail = "synthetic subscription token"
	cause := errors.New("transport error containing a " + privateDetail)
	remote := &ProviderRemote{
		ctx:          t.Context(),
		logger:       log.NewNOPFactory().NewLogger("test"),
		dialer:       failingProviderDialer{err: cause},
		url:          "https://example.com/subscription",
		encryptedURL: true,
	}
	err := remote.Update()
	if err == nil {
		t.Fatal("failed update was reported as a success")
	}
	if strings.Contains(err.Error(), privateDetail) || errors.Is(err, cause) {
		t.Fatal("update error exposed the private transport error")
	}
}

type failingProviderDialer struct {
	systemTestDialer
	err error
}

func (d failingProviderDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, d.err
}

type errorRecordingLogger struct {
	log.ContextLogger
	errors int
}

func (l *errorRecordingLogger) Error(args ...any) { l.errors++ }

// A failed update reaches the log whichever path asked for it: the dashboard refreshes every
// subscription at once, and only the log names the provider.
func TestProviderUpdateLogsAFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	logger := &errorRecordingLogger{ContextLogger: log.NewNOPFactory().NewLogger("test")}
	remote := &ProviderRemote{ctx: ctx, cancel: cancel, logger: logger}
	if err := remote.Update(); err == nil {
		t.Fatal("a canceled update was reported as a success")
	}
	if logger.errors != 1 {
		t.Fatalf("a failed update wrote %d error lines, expected 1", logger.errors)
	}
}

type systemTestDialer struct{}

func (systemTestDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return new(net.Dialer).DialContext(ctx, network, destination.String())
}

func (systemTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not supported")
}

// An expired account answers with no servers and explains why in the metadata headers, which must
// not be discarded with the body.
func TestFailedProviderUpdateKeepsTheMetadataItDelivered(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("profile-title", "Test Panel")
		w.Header().Set("announce", "top up your balance")
		w.Header().Set("Etag", "\"empty\"")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
	}))
	defer server.Close()

	logger := log.NewNOPFactory().NewLogger("test")
	remote := &ProviderRemote{
		ctx:       context.Background(),
		logger:    logger,
		url:       server.URL,
		userAgent: "sing-box",
		dialer:    systemTestDialer{},
		lastEtag:  "\"before\"",
	}
	remote.setSubscriptionData(adapter.SubscriptionInfo{}, adapter.SubscriptionMetadata{
		Title:    "Test Panel",
		Announce: "less than an hour remaining",
		// A field the failed response says nothing about survives the merge.
		SupportURL: "https://example.com/support",
	})

	if err := remote.fetch(context.Background()); err == nil {
		t.Fatal("a subscription with no servers was accepted")
	}
	metadata := remote.SubscriptionMetadata()
	if metadata.Announce != "top up your balance" {
		t.Fatalf("the failed update did not keep the notice it delivered: %q", metadata.Announce)
	}
	if metadata.SupportURL != "https://example.com/support" {
		t.Fatalf("the failed update dropped metadata the response said nothing about: %q", metadata.SupportURL)
	}
	if !remote.UpdatedAt().IsZero() {
		t.Fatalf("a failed update was recorded as one that succeeded: %s", remote.UpdatedAt())
	}
	// Keeping the etag would answer the next request with a 304 that reads as a
	// success, hiding the failure for as long as the panel stayed broken.
	if remote.etag() != "\"before\"" {
		t.Fatalf("a failed update stored its etag: %q", remote.etag())
	}
}

// Remnawave answers a device it does not take with 200, headers that say why, its notice and,
// in place of the servers, a list of notes or nothing.
func TestProviderUpdateNamesTheDeviceRefusal(t *testing.T) {
	for header, reason := range map[string]string{
		"x-hwid-max-devices-reached": "the provider refused this device: the subscription's limit of devices is reached",
		"x-hwid-not-supported":       "the provider refused this device: it requires the X-HWID header",
		"x-hwid-limit":               "the provider refused this device: it did not take the X-HWID of this device",
	} {
		t.Run(header, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(header, "true")
				w.Header().Set("x-hwid-limit", "true")
				w.Header().Set("announce", "delete a device in the bot")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?security=none#Device%20limit%20reached\n"))
			}))
			defer server.Close()

			remote := &ProviderRemote{
				ctx:       context.Background(),
				logger:    log.NewNOPFactory().NewLogger("test"),
				url:       server.URL,
				userAgent: "sing-box",
				dialer:    systemTestDialer{},
			}
			err := remote.fetch(context.Background())
			if err == nil || err.Error() != reason {
				t.Fatalf("the refusal was reported as %v", err)
			}
			if announce := remote.SubscriptionMetadata().Announce; announce != "delete a device in the bot" {
				t.Fatalf("the refusal lost the notice it came with: %q", announce)
			}
		})
	}
}

// A request that never reached the panel carries no headers, so it must not
// blank the metadata the provider already had.
func TestUnreachableProviderKeepsTheMetadataItAlreadyHad(t *testing.T) {
	remote := &ProviderRemote{ctx: context.Background(), logger: log.NewNOPFactory().NewLogger("test")}
	remote.setSubscriptionData(adapter.SubscriptionInfo{}, adapter.SubscriptionMetadata{Announce: "kept"})
	remote.applyFailedFetch(providerFetchResult{})
	if announce := remote.SubscriptionMetadata().Announce; announce != "kept" {
		t.Fatalf("an unreachable provider blanked its metadata: %q", announce)
	}
}

func TestProviderCloseWaitsForUpdate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	remote := &ProviderRemote{ctx: ctx, cancel: cancel}
	remote.updateAccess.Lock()
	done := make(chan struct{})
	go func() {
		_ = remote.Close()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("provider closed while an update was still publishing")
	case <-time.After(50 * time.Millisecond):
	}
	remote.updateAccess.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("provider close did not finish after the update completed")
	}
}

func TestProviderUpdateWaitsForARunningUpdate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	logger := &errorRecordingLogger{ContextLogger: log.NewNOPFactory().NewLogger("test")}
	remote := &ProviderRemote{ctx: ctx, cancel: cancel, logger: logger}
	remote.updateAccess.Lock()
	done := make(chan error, 1)
	go func() { done <- remote.Update() }()
	select {
	case err := <-done:
		t.Fatalf("an update running elsewhere failed this one: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	remote.updateAccess.Unlock()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("the waiting update did not run after the other one: %v", err)
	}
}

func TestProviderWithoutUpdateIntervalDisablesScheduledUpdates(t *testing.T) {
	provider, err := NewProviderRemote(
		service.ContextWith[adapter.OutboundManager](context.Background(), nil),
		nil,
		log.NewNOPFactory(),
		"manual",
		option.ProviderRemoteOptions{URL: "https://example.com/subscription"},
	)
	if err != nil {
		t.Fatal(err)
	}
	remote := provider.(*ProviderRemote)
	if remote.updateInterval != 0 {
		t.Fatalf("missing update_interval did not disable scheduled updates: %v", remote.updateInterval)
	}

	// Start leaves the ticker unset for a provider that has cached content, so a
	// later reset must tolerate that.
	remote.resetUpdateTicker(0)

	// Without cached content the first download may still use a retry ticker;
	// once it succeeds the reset has to stop that ticker, as Reset(0) panics.
	remote.ticker = time.NewTicker(time.Minute)
	defer remote.ticker.Stop()
	remote.resetUpdateTicker(remote.nextUpdateInterval(nil))
	select {
	case <-remote.ticker.C:
		t.Fatal("stopped retry ticker still fired")
	case <-time.After(20 * time.Millisecond):
	}
}

type externalRecordingDialer struct {
	systemTestDialer
	external bool
}

func (d *externalRecordingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.external = interrupt.IsExternalConnectionFromContext(ctx)
	return d.systemTestDialer.DialContext(ctx, network, destination)
}

// The download is dialed as an external connection, so that a group switching members does
// not close it together with its own connections.
func TestProviderDownloadIsExternalConnection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	dialer := new(externalRecordingDialer)
	remote := &ProviderRemote{
		ctx:       context.Background(),
		logger:    log.NewNOPFactory().NewLogger("test"),
		url:       server.URL,
		userAgent: "sing-box",
		dialer:    dialer,
	}
	if err := remote.Update(); err == nil {
		t.Fatal("a failed download was reported as a success")
	}
	if !dialer.external {
		t.Fatal("the subscription download was dialed as an internal connection")
	}
}
