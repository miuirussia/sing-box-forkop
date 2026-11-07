package schema

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/sagernet/sing/common/json/badoption"
)

func TestGenerateRegexpFields(t *testing.T) {
	t.Parallel()
	type options struct {
		Pattern badoption.Regexp  `json:"pattern"`
		Include *badoption.Regexp `json:"include,omitempty"`
		Exclude *badoption.Regexp `json:"exclude,omitempty"`
	}
	content, err := Generate(context.Background(), reflect.TypeFor[options]())
	if err != nil {
		t.Fatal(err)
	}
	var root Node
	if err = json.Unmarshal(content, &root); err != nil {
		t.Fatal(err)
	}
	definition, ok := root.Defs.Get("options")
	if !ok {
		t.Fatal("missing options definition")
	}
	for _, name := range []string{"pattern", "include", "exclude"} {
		t.Run(name, func(t *testing.T) {
			field, ok := definition.Properties.Get(name)
			if !ok || field.Type != "string" {
				t.Fatalf("expected JSON string for %s: %+v", name, field)
			}
		})
	}
}

func TestGenerateArbitraryJSONMap(t *testing.T) {
	t.Parallel()
	content, err := Generate(context.Background(), reflect.TypeFor[map[string]any]())
	if err != nil {
		t.Fatal(err)
	}
	var root Node
	if err = json.Unmarshal(content, &root); err != nil {
		t.Fatal(err)
	}
	additional, ok := root.AdditionalProperties.(map[string]any)
	if root.Type != "object" || !ok || len(additional) != 0 {
		t.Fatalf("expected unrestricted JSON map values, got %s", content)
	}
}
