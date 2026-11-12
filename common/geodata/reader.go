// Package geodata reads V2Ray GeoSiteList/GeoIPList protobuf files without
// materializing the database. Only the index and the selected tag occupy heap.
package geodata

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

const FormatVersion = 1

type Entry struct {
	Name   string `json:"name"`
	Count  int    `json:"count"`
	Offset int64  `json:"offset"`
	Length int64  `json:"length"`
}

type Catalog struct {
	Version  int     `json:"version"`
	Kind     string  `json:"kind"`
	Size     int64   `json:"size"`
	Mtime    string  `json:"mtime"`
	SHA256   string  `json:"sha256"`
	TagCount int     `json:"tag_count"`
	Tags     []Entry `json:"tags"`
}

func ValidKind(kind string) bool { return kind == "geosite" || kind == "geoip" }

// NormalizeTag also accepts a geosite attribute filter, for example google@cn.
func NormalizeTag(tag string) (string, error) {
	tag = strings.ToLower(strings.TrimSpace(tag))
	if tag == "" || len(tag) > 256 || strings.Count(tag, "@") > 1 {
		return "", fmt.Errorf("invalid geodata tag %q", tag)
	}
	for _, part := range strings.Split(tag, "@") {
		if part == "" || part == "!" {
			return "", fmt.Errorf("invalid geodata tag %q", tag)
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.!+", c)) {
				return "", fmt.Errorf("invalid geodata tag %q", tag)
			}
		}
	}
	return tag, nil
}

// Index hashes and scans the file once, discarding item payloads through a
// fixed 32 KiB buffer. Protobuf fields may appear in any order.
func Index(path, kind string) (*Catalog, error) {
	if !ValidKind(kind) {
		return nil, fmt.Errorf("unknown geodata kind %q", kind)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() == 0 {
		return nil, fmt.Errorf("empty or non-regular geodata file")
	}
	hash := sha256.New()
	w := newWire(io.TeeReader(f, hash))
	catalog := &Catalog{Version: FormatVersion, Kind: kind, Size: st.Size(), Mtime: fmt.Sprint(st.ModTime().UnixNano())}
	seen := make(map[string]bool)
	for w.pos < st.Size() {
		field, wireType, err := w.tag(st.Size())
		if err != nil {
			return nil, err
		}
		if field != 1 || wireType != 2 {
			if err = w.skip(wireType, st.Size()); err != nil {
				return nil, err
			}
			continue
		}
		end, err := w.message(st.Size())
		if err != nil {
			return nil, err
		}
		entry := Entry{Offset: w.pos, Length: end - w.pos}
		for w.pos < end {
			field, wireType, err = w.tag(end)
			if err != nil {
				return nil, err
			}
			switch {
			case field == 1 && wireType == 2:
				entry.Name, err = w.text(end, 256)
			case field == 2 && wireType == 2:
				entry.Count++
				err = w.skip(wireType, end)
			default:
				err = w.skip(wireType, end)
			}
			if err != nil {
				return nil, err
			}
		}
		entry.Name, err = NormalizeTag(entry.Name)
		if err != nil || strings.Contains(entry.Name, "@") || seen[entry.Name] {
			return nil, fmt.Errorf("invalid or duplicate geodata entry %q", entry.Name)
		}
		if len(catalog.Tags) >= 32768 {
			return nil, fmt.Errorf("too many geodata tags")
		}
		seen[entry.Name] = true
		catalog.Tags = append(catalog.Tags, entry)
	}
	if len(catalog.Tags) == 0 {
		return nil, fmt.Errorf("geodata contains no tags")
	}
	after, err := f.Stat()
	if err != nil || after.Size() != st.Size() || !after.ModTime().Equal(st.ModTime()) {
		return nil, fmt.Errorf("geodata changed while indexing")
	}
	catalog.SHA256 = hex.EncodeToString(hash.Sum(nil))
	catalog.TagCount = len(catalog.Tags)
	sort.Slice(catalog.Tags, func(i, j int) bool { return catalog.Tags[i].Name < catalog.Tags[j].Name })
	return catalog, nil
}

type wire struct {
	reader *bufio.Reader
	pos    int64
}

func newWire(r io.Reader) *wire { return &wire{reader: bufio.NewReaderSize(r, 32*1024)} }

func (w *wire) varint(end int64) (uint64, error) {
	var value uint64
	for shift := uint(0); shift < 70; shift += 7 {
		if w.pos >= end {
			return 0, io.ErrUnexpectedEOF
		}
		b, err := w.reader.ReadByte()
		if err != nil {
			return 0, err
		}
		w.pos++
		if shift == 63 && b > 1 {
			return 0, fmt.Errorf("protobuf varint overflow")
		}
		value |= uint64(b&0x7f) << shift
		if b < 0x80 {
			return value, nil
		}
	}
	return 0, fmt.Errorf("protobuf varint overflow")
}

func (w *wire) tag(end int64) (int, int, error) {
	v, err := w.varint(end)
	if err != nil {
		return 0, 0, err
	}
	if v>>3 == 0 || v>>3 > (1<<29)-1 {
		return 0, 0, fmt.Errorf("invalid protobuf field")
	}
	return int(v >> 3), int(v & 7), nil
}

func (w *wire) message(end int64) (int64, error) {
	n, err := w.varint(end)
	if err != nil {
		return 0, err
	}
	if n > uint64(end-w.pos) {
		return 0, io.ErrUnexpectedEOF
	}
	return w.pos + int64(n), nil
}

func (w *wire) discard(n, end int64) error {
	if n < 0 || n > end-w.pos {
		return io.ErrUnexpectedEOF
	}
	for n > 0 {
		count, err := w.reader.Discard(int(min(n, 32*1024)))
		w.pos += int64(count)
		n -= int64(count)
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *wire) skip(wireType int, end int64) error {
	switch wireType {
	case 0:
		_, err := w.varint(end)
		return err
	case 1:
		return w.discard(8, end)
	case 2:
		next, err := w.message(end)
		if err != nil {
			return err
		}
		return w.discard(next-w.pos, end)
	case 5:
		return w.discard(4, end)
	default:
		return fmt.Errorf("unsupported protobuf wire type %d", wireType)
	}
}

func (w *wire) text(end int64, limit int64) (string, error) {
	next, err := w.message(end)
	if err != nil {
		return "", err
	}
	if next-w.pos > limit {
		return "", fmt.Errorf("geodata string exceeds %d bytes", limit)
	}
	value, err := w.reader.Peek(int(next - w.pos))
	if err != nil {
		return "", err
	}
	text := string(value)
	err = w.discard(next-w.pos, end)
	return text, err
}
