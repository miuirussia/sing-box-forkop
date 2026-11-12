package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

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
