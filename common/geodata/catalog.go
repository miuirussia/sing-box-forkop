package geodata

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

// scanCatalog decodes one index entry at a time. Catalog pagination and the
// exporter do not need to allocate the full JSON index again.
func scanCatalog(path string, visit func(Entry)) (*Catalog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 16<<20))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, fmt.Errorf("invalid geodata index")
	}
	catalog := &Catalog{}
	count := 0
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		switch key {
		case "version":
			err = decoder.Decode(&catalog.Version)
		case "kind":
			err = decoder.Decode(&catalog.Kind)
		case "size":
			err = decoder.Decode(&catalog.Size)
		case "mtime":
			err = decoder.Decode(&catalog.Mtime)
		case "sha256":
			err = decoder.Decode(&catalog.SHA256)
		case "tag_count":
			err = decoder.Decode(&catalog.TagCount)
		case "tags":
			var token json.Token
			token, err = decoder.Token()
			if err == nil && token != json.Delim('[') {
				err = fmt.Errorf("invalid geodata index tags")
			}
			if err != nil {
				return nil, err
			}
			var entry Entry
			for decoder.More() {
				entry = Entry{}
				if err = decoder.Decode(&entry); err != nil {
					return nil, err
				}
				count++
				if count > 32768 {
					return nil, fmt.Errorf("too many index entries")
				}
				visit(entry)
			}
			_, err = decoder.Token()
		default:
			return nil, fmt.Errorf("unknown geodata index field %v", key)
		}
		if err != nil {
			return nil, err
		}
	}
	if _, err = decoder.Token(); err != nil {
		return nil, err
	}
	if catalog.Version != FormatVersion || !ValidKind(catalog.Kind) || count == 0 || count != catalog.TagCount {
		return nil, fmt.Errorf("invalid geodata index metadata")
	}
	return catalog, nil
}

func LoadTagCatalog(path, indexPath, kind, tag string) (*Catalog, error) {
	return LoadTagCatalogs(
		path,
		indexPath,
		kind,
		[]string{tag},
	)
}

// LoadTagCatalogs scans the index once and retains only the requested base tags.
func LoadTagCatalogs(path, indexPath, kind string, tags []string) (*Catalog, error) {
	entries := make(map[string]Entry, len(tags))
	bases := make([]string, 0, len(tags))
	for _, tag := range tags {
		normalized, err := NormalizeTag(tag)
		if err != nil {
			return nil, err
		}
		base, _, _ := strings.Cut(normalized, "@")
		if _, exists := entries[base]; !exists {
			bases = append(bases, base)
			entries[base] = Entry{}
		}
	}
	var duplicate string
	catalog, err := scanCatalog(indexPath, func(entry Entry) {
		if selected, ok := entries[entry.Name]; ok {
			if selected.Name != "" {
				duplicate = entry.Name
			}
			entries[entry.Name] = entry
		}
	})
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if catalog.Kind != kind || catalog.Size != st.Size() || catalog.Mtime != fmt.Sprint(st.ModTime().UnixNano()) {
		return nil, fmt.Errorf("stale geodata index")
	}
	if duplicate != "" {
		return nil, fmt.Errorf("duplicate geodata index entry for tag %q", duplicate)
	}
	catalog.Tags = make([]Entry, 0, len(entries))
	for _, tag := range bases {
		entry := entries[tag]
		invalidOffset := entry.Offset < 0 || entry.Offset > st.Size()
		if entry.Name == "" || invalidOffset || entry.Length < 0 || entry.Length > st.Size()-entry.Offset {
			return nil, fmt.Errorf("tag %q not found or invalid geodata index bounds", tag)
		}
		catalog.Tags = append(catalog.Tags, entry)
	}
	slices.SortFunc(catalog.Tags, func(a, b Entry) int { return cmp.Compare(a.Name, b.Name) })
	return catalog, nil
}

type Tag struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type TagPage struct {
	Tags   []Tag `json:"tags"`
	Total  int   `json:"total"`
	Offset int   `json:"offset"`
}

func ListTags(indexPath, search string, offset int) (*TagPage, error) {
	page := &TagPage{Tags: []Tag{}, Offset: max(0, offset)}
	search = strings.ToLower(strings.TrimSpace(search))
	_, err := scanCatalog(indexPath, func(entry Entry) {
		if !strings.Contains(entry.Name, search) {
			return
		}
		if page.Total >= page.Offset && len(page.Tags) < 200 {
			page.Tags = append(page.Tags, Tag{Name: entry.Name, Count: entry.Count})
		}
		page.Total++
	})
	return page, err
}
