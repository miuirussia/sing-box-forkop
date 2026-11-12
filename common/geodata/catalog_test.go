package geodata

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestListTags(t *testing.T) {
	t.Parallel()
	var data []byte
	for i := range 450 {
		data = append(data, geoEntry(fmt.Sprintf("tag-%03d", i), domainItem(3, "example.com", ""))...)
	}
	path := database(t, data)
	catalog, err := Index(path, "geosite")
	if err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(t.TempDir(), "index.json")
	index, _ := json.Marshal(catalog)
	if err = os.WriteFile(indexPath, index, 0600); err != nil {
		t.Fatal(err)
	}
	page, err := ListTags(indexPath, "", 200)
	if err != nil || page.Total != 450 || len(page.Tags) != 200 || page.Tags[0].Name != "tag-200" {
		t.Fatalf("invalid page: %+v, %v", page, err)
	}
	page, err = ListTags(indexPath, "TAG-44", 0)
	if err != nil || page.Total != 10 || len(page.Tags) != 10 {
		t.Fatalf("invalid filter: %+v, %v", page, err)
	}
	selected, err := LoadTagCatalog(path, indexPath, "geosite", "tag-220")
	if err != nil || len(selected.Tags) != 1 || selected.Tags[0].Name != "tag-220" {
		t.Fatalf("invalid selection: %+v, %v", selected, err)
	}
	if _, err = LoadTagCatalog(path, indexPath, "geoip", "tag-220"); err == nil {
		t.Fatal("accepted wrong kind")
	}
	if _, err = LoadTagCatalog(path, indexPath, "geosite", "missing"); err == nil {
		t.Fatal("accepted missing tag")
	}
}
