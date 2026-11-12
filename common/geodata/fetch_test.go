package geodata

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		status int
		body   string
		length string
		valid  bool
	}{
		{"success", 200, "data", "", true}, {"empty", 200, "", "", false},
		{"not found", 404, "not found", "", false}, {"size limit", 200, "", "134217729", false},
		{"truncated", 200, "short", "100", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if test.length != "" {
					w.Header().Set("Content-Length", test.length)
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			var output bytes.Buffer
			err := Fetch(context.Background(), server.URL, &output)
			if (err == nil) != test.valid {
				t.Fatalf("Fetch error = %v", err)
			}
			if test.valid && output.String() != test.body {
				t.Fatal("body changed")
			}
		})
	}
	if err := Fetch(context.Background(), "file:///etc/passwd", &bytes.Buffer{}); err == nil {
		t.Fatal("accepted file URL")
	}
}
