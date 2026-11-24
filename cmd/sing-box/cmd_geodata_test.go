package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/srs"
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

func TestGeodataExportBatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "source.dat")
	data := []byte{
		10, 25, 10, 4, 't', 'e', 's', 't',
		18, 10, 8, 3, 18, 1, 'x', 26, 3, 10, 1, 'a', // exact domain x with attribute a
		18, 5, 8, 3, 18, 1, 'y', // exact domain y without attributes
		10, 13, 10, 4, 'o', 't', 'h', 'r', 18, 5, 8, 3, 18, 1, 'z', // second tag
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(dir, "index.json")
	command := newGeodataCommand()
	command.SetArgs([]string{"list", "--kind", "geosite", "--file", path, "--output", index})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		manifest string
		domains  map[string]string
		error    string
	}{
		{
			name:     "distinct tags and attribute filters",
			manifest: `["test@a", "test@!a", "othr", "TEST@A"]`,
			domains:  map[string]string{"test@a.srs": "x", "test@!a.srs": "y", "othr.srs": "z"},
		},
		{name: "missing tags in request order", manifest: `["test", "second", "first"]`, error: `tag "second" not found`},
		{name: "invalid tag", manifest: `["test", "../unexpected"]`, error: `invalid geodata tag`},
		{name: "manifest with trailing data", manifest: `["test"] false`, error: `unexpected data`},
		{
			name:     "a failed export preserves earlier files",
			manifest: `["othr", "test@missing"]`,
			domains:  map[string]string{"othr.srs": "z"},
			error:    `tag "test@missing" is empty`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := t.TempDir()
			tags := filepath.Join(t.TempDir(), "tags.json")
			if err := os.WriteFile(tags, []byte(test.manifest), 0600); err != nil {
				t.Fatal(err)
			}
			command := newGeodataCommand()
			command.SetArgs([]string{
				"export", "--kind", "geosite", "--file", path, "--index", index,
				"--tags-file", tags, "--output", output,
			})
			command.SetErr(&bytes.Buffer{})
			command.SetOut(&bytes.Buffer{})
			err := command.Execute()
			if test.error == "" && err != nil {
				t.Fatal(err)
			}
			if test.error != "" && (err == nil || !strings.Contains(err.Error(), test.error)) {
				t.Fatalf("got error %v, want %q", err, test.error)
			}
			files, err := os.ReadDir(output)
			if err != nil || len(files) != len(test.domains) {
				t.Fatalf("got %d exports, want %d: %v", len(files), len(test.domains), err)
			}
			for filename, domain := range test.domains {
				data, err := os.ReadFile(filepath.Join(output, filename))
				if err != nil {
					t.Fatal(err)
				}
				set, err := srs.Read(bytes.NewReader(data), true)
				if err != nil || len(set.Options.Rules) != 1 {
					t.Fatalf("invalid SRS %q: %v", filename, err)
				}
				if got := set.Options.Rules[0].DefaultOptions.Domain; !slices.Equal(got, []string{domain}) {
					t.Errorf("%s matches %v, want %q", filename, got, domain)
				}
			}
		})
	}
}

func TestReadGeodataTagsLimits(t *testing.T) {
	t.Parallel()
	t.Run("oversized file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "tags.json")
		if err := os.WriteFile(path, []byte(`["test"]`), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(path, (16<<20)+1); err != nil {
			t.Fatal(err)
		}
		if _, err := readGeodataTags(path); err == nil || !strings.Contains(err.Error(), "exceeds 16 MiB") {
			t.Fatalf("expected the file size limit error, got %v", err)
		}
	})
	t.Run("too many distinct tags", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "tags.json")
		var manifest strings.Builder
		manifest.WriteString(`["test"`)
		for i := range 32768 {
			fmt.Fprintf(&manifest, `,"test@%d"`, i)
		}
		manifest.WriteByte(']')
		if err := os.WriteFile(path, []byte(manifest.String()), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readGeodataTags(path); err == nil || !strings.Contains(err.Error(), "too many distinct geodata tags") {
			t.Fatalf("expected the distinct tag limit error, got %v", err)
		}
	})
}
