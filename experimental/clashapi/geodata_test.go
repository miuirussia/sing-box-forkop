package clashapi

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

type geodataTransport struct{ response *http.Response }

func (t *geodataTransport) RoundTrip(*http.Request) (*http.Response, error) { return t.response, nil }
func (*geodataTransport) CloseIdleConnections()                             {}
func (*geodataTransport) Reset()                                            {}

type geodataHTTPManager struct {
	adapter.HTTPClientManager
	detour string
}

func (m *geodataHTTPManager) ResolveTransport(_ context.Context, _ logger.ContextLogger, options option.HTTPClientOptions) (adapter.HTTPTransport, error) {
	m.detour = options.Detour
	return &geodataTransport{&http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("DAT content")), Header: make(http.Header)}}, nil
}

type geodataResponseRecorder struct {
	*httptest.ResponseRecorder
}

func (*geodataResponseRecorder) SetWriteDeadline(time.Time) error { return nil }

func TestDownloadGeodata(t *testing.T) {
	t.Parallel()
	manager := &geodataHTTPManager{}
	server := &Server{ctx: service.ContextWith[adapter.HTTPClientManager](context.Background(), manager)}
	request := httptest.NewRequest(http.MethodPost, "/geodata/download", strings.NewReader(`{"url":"https://example.com/geosite.dat","detour":"vpn"}`))
	request.RemoteAddr = "127.0.0.1:12345"
	recorder := &geodataResponseRecorder{httptest.NewRecorder()}
	server.downloadGeodata(recorder, request)
	if recorder.Code != 200 || recorder.Body.String() != "DAT content\nFORKOP-GEODATA-DONE\n" || manager.detour != "vpn" {
		t.Fatalf("invalid download: %d %s via %s", recorder.Code, recorder.Body, manager.detour)
	}
	request = httptest.NewRequest(http.MethodPost, "/geodata/download", strings.NewReader(`{"url":"https://example.com/geosite.dat"}`))
	request.RemoteAddr = "192.0.2.1:12345"
	request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 9090}))
	recorder = &geodataResponseRecorder{httptest.NewRecorder()}
	server.downloadGeodata(recorder, request)
	if recorder.Code != 200 {
		t.Fatalf("router-local LAN connection rejected: %d", recorder.Code)
	}
	for _, test := range []struct {
		name, remote, body string
		status             int
	}{
		{"remote peer", "192.0.2.1:1234", `{}`, 403},
		{"bad URL", "127.0.0.1:1234", `{"url":"file:///etc/passwd"}`, 400},
		{"credentials", "127.0.0.1:1234", `{"url":"https://user:pass@example.com/"}`, 400},
		{"bad JSON", "127.0.0.1:1234", `{`, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/geodata/download", strings.NewReader(test.body))
			request.RemoteAddr = test.remote
			recorder := httptest.NewRecorder()
			server.downloadGeodata(recorder, request)
			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d", recorder.Code, test.status)
			}
		})
	}
}

type geodataBlockedResponseWriter struct {
	http.ResponseWriter
	net.Conn
}

func (w *geodataBlockedResponseWriter) Write(p []byte) (int, error) { return w.Conn.Write(p) }

func TestDownloadGeodataWriteDeadline(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		acceptBody bool
	}{
		{"blocked body", false},
		{"blocked completion marker", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				manager := &geodataHTTPManager{}
				server := &Server{ctx: service.ContextWith[adapter.HTTPClientManager](context.Background(), manager)}
				request := httptest.NewRequest(http.MethodPost, "/geodata/download", strings.NewReader(`{"url":"https://example.com/geosite.dat"}`))
				request.RemoteAddr = "127.0.0.1:12345"
				writer, reader := net.Pipe()
				defer writer.Close()
				defer reader.Close()
				done := make(chan struct{})
				go func() {
					server.downloadGeodata(&geodataBlockedResponseWriter{httptest.NewRecorder(), writer}, request)
					close(done)
				}()
				if test.acceptBody {
					if _, err := io.CopyN(io.Discard, reader, int64(len("DAT content"))); err != nil {
						t.Fatal(err)
					}
				}
				synctest.Wait()
				select {
				case <-done:
					t.Fatal("download returned before its write deadline")
				default:
				}
				select {
				case <-done:
				case <-time.After(11 * time.Minute):
					t.Fatal("download did not stop writing after its deadline")
				}
				if !server.geodataAccess.TryLock() {
					t.Fatal("download did not release its lock")
				}
				server.geodataAccess.Unlock()
			})
		})
	}
}
