package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestGeodataFetchAtomic(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/truncated" {
			w.Header().Set("Content-Length", "100")
		}
		if _, err := w.Write([]byte("valid-dat")); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	tests := []struct {
		name string
		mark string
		path string
		ok   bool
	}{
		{name: "unmarked", mark: "0", path: "/ok", ok: true},
		{name: "truncated", mark: "0", path: "/truncated"},
		{name: "negative mark", mark: "-1", path: "/ok"},
		{name: "overflow mark", mark: "0x100000000", path: "/ok"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "source.dat")
			if err := os.WriteFile(output, []byte("previous"), 0600); err != nil {
				t.Fatal(err)
			}
			command := newGeodataCommand()
			command.SetArgs([]string{
				"fetch", "--url", server.URL + test.path,
				"--output", output, "--routing-mark", test.mark,
			})
			command.SetErr(&bytes.Buffer{})
			command.SetOut(&bytes.Buffer{})
			if err := command.Execute(); (err == nil) != test.ok {
				t.Fatalf("fetch error = %v, want success %v", err, test.ok)
			}
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			want := "previous"
			if test.ok {
				want = "valid-dat"
			}
			if string(data) != want {
				t.Fatalf("download = %q, want %q", data, want)
			}
		})
	}
}

func TestGeodataExportAtomic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "source.dat")
	// GeoSiteList entry, with one exact domain "x" under tag "test".
	data := []byte{10, 13, 10, 4, 't', 'e', 's', 't', 18, 5, 8, 3, 18, 1, 'x'}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(dir, "index.json")
	command := newGeodataCommand()
	command.SetArgs([]string{"list", "--kind", "geosite", "--file", path, "--output", index})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "tag.srs")
	command = newGeodataCommand()
	command.SetArgs([]string{"export", "--kind", "geosite", "--file", path, "--index", index, "--tag", "test", "--output", output})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	working, err := os.ReadFile(output)
	if err != nil || !bytes.HasPrefix(working, []byte("SRS")) {
		t.Fatalf("invalid SRS: %v", err)
	}
	command = newGeodataCommand()
	command.SetArgs([]string{"export", "--kind", "geosite", "--file", path, "--index", index, "--tag", "missing", "--output", output})
	command.SetErr(&bytes.Buffer{})
	command.SetOut(&bytes.Buffer{})
	if err = command.Execute(); err == nil {
		t.Fatal("accepted missing tag")
	}
	after, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(working, after) {
		t.Fatal("failed export replaced the working SRS")
	}
}
