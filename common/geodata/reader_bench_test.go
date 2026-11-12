package geodata

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func largeDatabase(b *testing.B, count int) string {
	b.Helper()
	path := filepath.Join(b.TempDir(), "large.dat")
	f, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	w := bufio.NewWriterSize(f, 64*1024)
	item := message(2, domainItem(2, "example.com", ""))
	name := message(1, []byte("large"))
	header := binary.AppendUvarint([]byte{0x0a}, uint64(len(name)+count*len(item)))
	if _, err = w.Write(header); err != nil {
		b.Fatal(err)
	}
	if _, err = w.Write(name); err != nil {
		b.Fatal(err)
	}
	for range count {
		if _, err = w.Write(item); err != nil {
			b.Fatal(err)
		}
	}
	if _, err = w.Write(geoEntry("small", domainItem(3, "exact.example", ""))); err != nil {
		b.Fatal(err)
	}
	if err = w.Flush(); err != nil {
		b.Fatal(err)
	}
	if err = f.Close(); err != nil {
		b.Fatal(err)
	}
	return path
}

func BenchmarkIndex(b *testing.B) {
	for _, count := range []int{4096, 4 * 1024 * 1024} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			path := largeDatabase(b, count)
			st, _ := os.Stat(path)
			b.SetBytes(st.Size())
			b.ReportAllocs()
			for b.Loop() {
				if _, err := Index(path, "geosite"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkExportSmallTag(b *testing.B) {
	for _, count := range []int{4096, 4 * 1024 * 1024} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			path := largeDatabase(b, count)
			catalog, err := Index(path, "geosite")
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if err = Export(path, catalog, "small", io.Discard); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
