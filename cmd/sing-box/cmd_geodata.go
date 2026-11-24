package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/sagernet/sing-box/common/geodata"

	"github.com/spf13/cobra"
)

const (
	maxGeodataTagsBytes = 16 << 20
	maxGeodataTags      = 32768
)

func init() { mainCommand.AddCommand(newGeodataCommand()) }

func newGeodataCommand() *cobra.Command {
	var kind, path string
	command := &cobra.Command{Use: "geodata", Short: "Read V2Ray geosite/geoip DAT files"}
	command.PersistentFlags().StringVar(&kind, "kind", "", "Database kind: geosite or geoip")
	command.PersistentFlags().StringVarP(&path, "file", "f", "", "Input DAT file")
	var indexOutput, summaryOutput string
	list := &cobra.Command{
		Use: "list", Short: "Index tags and counts as JSON using bounded memory", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			catalog, err := geodata.Index(path, kind)
			if err != nil {
				return err
			}
			if summaryOutput != "" {
				summary := *catalog
				summary.Tags = nil
				if err = writeGeodataFile(summaryOutput, func(w io.Writer) error { return json.NewEncoder(w).Encode(summary) }); err != nil {
					return err
				}
			}
			write := func(w io.Writer) error { return json.NewEncoder(w).Encode(catalog) }
			if indexOutput == "" {
				return write(cmd.OutOrStdout())
			}
			return writeGeodataFile(indexOutput, write)
		},
	}
	list.Flags().StringVar(&indexOutput, "output", "", "Write the reusable index to this file")
	list.Flags().StringVar(&summaryOutput, "summary", "", "Write metadata without the tag index to this file")
	list.PreRunE = func(_ *cobra.Command, _ []string) error {
		if path == "" || !geodata.ValidKind(kind) {
			return fmt.Errorf("--file and --kind (geosite or geoip) are required")
		}
		return nil
	}
	var tag, tagsPath, indexPath, output string
	export := &cobra.Command{
		Use: "export", Short: "Compile DAT tags directly to SRS", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			requested := []string{tag}
			batch := cmd.Flags().Changed("tags-file")
			if batch {
				if output == "" {
					return fmt.Errorf("--output must name the batch output directory")
				}
				var err error
				requested, err = readGeodataTags(tagsPath)
				if err != nil {
					return err
				}
			}
			var catalog *geodata.Catalog
			var err error
			if indexPath == "" {
				catalog, err = geodata.Index(path, kind)
			} else {
				catalog, err = geodata.LoadTagCatalogs(
					path,
					indexPath,
					kind,
					requested,
				)
			}
			if err != nil {
				return err
			}
			for _, tag := range requested {
				destination := output
				if batch {
					destination = filepath.Join(output, tag+".srs")
				}
				err = writeGeodataFile(destination, func(w io.Writer) error {
					return catalog.ExportIndexed(path, tag, w)
				})
				if err != nil {
					return fmt.Errorf("export geodata tag %q: %w", tag, err)
				}
			}
			return nil
		},
	}
	export.Flags().StringVar(&tag, "tag", "", "Tag, optionally with @attribute or @!attribute")
	export.Flags().StringVar(&tagsPath, "tags-file", "", "JSON array of tags to export in one batch")
	export.PreRunE = list.PreRunE
	export.Flags().StringVar(&indexPath, "index", "", "Reuse an index produced by geodata list")
	export.Flags().StringVarP(&output, "output", "o", "", "Output SRS file or directory when using --tags-file")
	export.MarkFlagsOneRequired("tag", "tags-file")
	export.MarkFlagsMutuallyExclusive("tag", "tags-file")
	_ = export.MarkFlagRequired("output")
	command.AddCommand(list, export)
	var address, destination string
	var routingMark uint32
	fetch := &cobra.Command{Use: "fetch", Short: "Download a DAT directly with bounded memory and size", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Minute)
			defer cancel()
			return writeGeodataFile(destination, func(w io.Writer) error {
				return geodata.Fetch(
					ctx,
					address,
					routingMark,
					w,
				)
			})
		},
	}
	// Fetch does not read a database, unlike list/export.
	fetch.Flags().StringVar(&address, "url", "", "HTTP(S) URL")
	fetch.Flags().StringVar(&destination, "output", "", "Destination file")
	fetch.Flags().Uint32Var(&routingMark, "routing-mark", 0, "Routing mark for download and DNS sockets")
	_ = fetch.MarkFlagRequired("url")
	_ = fetch.MarkFlagRequired("output")
	command.AddCommand(fetch)
	var tagsIndex, search string
	var offset int
	tags := &cobra.Command{Use: "tags", Short: "Search a cached DAT index, 200 tags per page", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			page, err := geodata.ListTags(tagsIndex, search, offset)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(page)
		},
	}
	tags.Flags().StringVar(&tagsIndex, "index", "", "Cached DAT index")
	tags.Flags().StringVar(&search, "search", "", "Tag name filter")
	tags.Flags().IntVar(&offset, "offset", 0, "Result offset")
	_ = tags.MarkFlagRequired("index")
	command.AddCommand(tags)
	return command
}

func readGeodataTags(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Mode().IsRegular() && info.Size() > maxGeodataTagsBytes {
		return nil, fmt.Errorf("geodata tags file exceeds 16 MiB")
	}
	reader := &io.LimitedReader{R: file, N: maxGeodataTagsBytes + 1}
	tags, err := decodeGeodataTags(reader)
	if reader.N == 0 {
		return nil, fmt.Errorf("geodata tags file exceeds 16 MiB")
	}
	return tags, err
}

func decodeGeodataTags(reader io.Reader) ([]string, error) {
	decoder := json.NewDecoder(reader)
	opening, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("read geodata tags: %w", err)
	}
	if opening != json.Delim('[') {
		return nil, fmt.Errorf("geodata tags file must contain a JSON array")
	}
	tags := []string{}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("read geodata tags: %w", err)
		}
		tag, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("geodata tags must be JSON strings")
		}
		tag, err = geodata.NormalizeTag(tag)
		if err != nil {
			return nil, err
		}
		if !seen[tag] {
			if len(tags) == maxGeodataTags {
				return nil, fmt.Errorf("too many distinct geodata tags (maximum %d)", maxGeodataTags)
			}
			seen[tag] = true
			tags = append(tags, tag)
		}
	}
	if _, err = decoder.Token(); err != nil {
		return nil, fmt.Errorf("read geodata tags: %w", err)
	}
	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("unexpected data after geodata tags array")
	}
	if len(tags) == 0 {
		return nil, fmt.Errorf("geodata tags file must contain at least one tag")
	}
	return tags, nil
}

func writeGeodataFile(path string, write func(io.Writer) error) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".geodata-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = write(f); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return fmt.Errorf("publish geodata: %w", err)
	}
	return nil
}
