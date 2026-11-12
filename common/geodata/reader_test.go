package geodata

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func uintField(field int, value uint64) []byte {
	b := binary.AppendUvarint(nil, uint64(field<<3))
	return binary.AppendUvarint(b, value)
}

func message(field int, content []byte) []byte {
	b := binary.AppendUvarint(nil, uint64(field<<3|2))
	b = binary.AppendUvarint(b, uint64(len(content)))
	return append(b, content...)
}

func geoEntry(name string, items ...[]byte) []byte {
	var content []byte
	// Put the name last: protobuf does not promise field ordering.
	for _, item := range items {
		content = append(content, message(2, item)...)
	}
	content = append(content, message(1, []byte(name))...)
	return message(1, content)
}

func database(t testing.TB, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "source.dat")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestIndex(t *testing.T) {
	t.Parallel()
	data := append(geoEntry("YOUTUBE", message(2, []byte("youtube.com"))), geoEntry("GOOGLE", message(2, []byte("google.com")))...)
	path := database(t, data)
	catalog, err := Index(path, "geosite")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	if len(catalog.Tags) != 2 || catalog.Tags[0].Name != "google" || catalog.Tags[1].Count != 1 || catalog.SHA256 != hex.EncodeToString(hash[:]) {
		t.Fatalf("invalid catalog: %+v", catalog)
	}
	index, _ := json.Marshal(catalog)
	indexPath := filepath.Join(t.TempDir(), "index.json")
	if err = os.WriteFile(indexPath, index, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadTagCatalog(path, indexPath, "geosite", "google"); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadTagCatalog(path, indexPath, "geoip", "google"); err == nil {
		t.Fatal("accepted index for a different kind")
	}
	if err = os.WriteFile(path, append(data, 0), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadTagCatalog(path, indexPath, "geosite", "google"); err == nil {
		t.Fatal("accepted a stale index")
	}
}

func TestIndexInvalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil}, {"truncated length", []byte{0x0a, 0x80}},
		{"oversized length", []byte{0x0a, 0xff, 0xff, 0xff, 0xff, 0x7f}},
		{"invalid wire type", []byte{0x0f}}, {"zero field", []byte{0}},
		{"overflow", bytes.Repeat([]byte{0xff}, 11)},
		{"duplicate", append(geoEntry("google"), geoEntry("GOOGLE")...)},
		{"path traversal", geoEntry("../escape")},
		{"long name", geoEntry(strings.Repeat("a", 257))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Index(database(t, test.data), "geosite"); err == nil {
				t.Fatal("accepted invalid database")
			}
		})
	}
}

func TestNormalizeTag(t *testing.T) {
	t.Parallel()
	for _, tag := range []string{"google", "google@cn", "google@!cn", "category-ads-all"} {
		if _, err := NormalizeTag(strings.ToUpper(tag)); err != nil {
			t.Fatal(err)
		}
	}
	for _, tag := range []string{"", "../tag", "x@y@z", "x@", "x@!", "x/y"} {
		if _, err := NormalizeTag(tag); err == nil {
			t.Fatalf("accepted %q", tag)
		}
	}
}
