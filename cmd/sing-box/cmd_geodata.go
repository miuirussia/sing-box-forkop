package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/sagernet/sing-box/common/geodata"

	"github.com/spf13/cobra"
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
	var tag, indexPath, output string
	export := &cobra.Command{
		Use: "export", Short: "Compile one DAT tag directly to SRS", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var catalog *geodata.Catalog
			var err error
			if indexPath == "" {
				catalog, err = geodata.Index(path, kind)
			} else {
				catalog, err = geodata.LoadTagCatalog(path, indexPath, kind, tag)
			}
			if err != nil {
				return err
			}
			return writeGeodataFile(output, func(w io.Writer) error { return geodata.Export(path, catalog, tag, w) })
		},
	}
	export.Flags().StringVar(&tag, "tag", "", "Tag, optionally with @attribute or @!attribute")
	export.PreRunE = list.PreRunE
	export.Flags().StringVar(&indexPath, "index", "", "Reuse an index produced by geodata list")
	export.Flags().StringVarP(&output, "output", "o", "", "Output SRS file")
	_ = export.MarkFlagRequired("tag")
	_ = export.MarkFlagRequired("output")
	command.AddCommand(list, export)
	var address, destination string
	fetch := &cobra.Command{Use: "fetch", Short: "Download a DAT directly with bounded memory and size", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Minute)
			defer cancel()
			return writeGeodataFile(destination, func(w io.Writer) error { return geodata.Fetch(ctx, address, w) })
		},
	}
	// Fetch does not read a database, unlike list/export.
	fetch.Flags().StringVar(&address, "url", "", "HTTP(S) URL")
	fetch.Flags().StringVar(&destination, "output", "", "Destination file")
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
