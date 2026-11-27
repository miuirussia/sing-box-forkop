package include

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/schema"
)

func TestGenerateConfigurationSchema(t *testing.T) {
	content, err := schema.Generate(Context(context.Background()), reflect.TypeFor[option.Options]())
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(content) {
		t.Fatal("configuration schema is not valid JSON")
	}
	var root schema.Node
	if err = json.Unmarshal(content, &root); err != nil {
		t.Fatal(err)
	}
	provider, ok := root.Defs.Get("Provider")
	if !ok {
		t.Fatal("missing provider schema")
	}
	var types []string
	for _, variant := range provider.OneOf {
		field, ok := variant.Properties.Get("type")
		if !ok {
			t.Fatal("provider variant has no type discriminator")
		}
		types = append(types, field.Const.(string))
	}
	if !reflect.DeepEqual(types, ProviderRegistry().OptionTypes()) {
		t.Fatalf("provider variants do not match registry: %v", types)
	}
}

func TestDesyncSchemaRegistered(t *testing.T) {
	content, err := schema.Generate(Context(context.Background()), reflect.TypeFor[option.Options]())
	if err != nil {
		t.Fatal(err)
	}
	var root schema.Node
	if err = json.Unmarshal(content, &root); err != nil {
		t.Fatal(err)
	}
	outbound, ok := root.Defs.Get("Outbound")
	if !ok {
		t.Fatal("missing outbound schema")
	}
	found := false
	variants := append([]*schema.Node(nil), outbound.OneOf...)
	for len(variants) > 0 {
		variant := variants[0]
		variants = variants[1:]
		if variant.Properties == nil {
			variants = append(variants, variant.OneOf...)
			continue
		}
		kind, ok := variant.Properties.Get("type")
		if !ok || kind.Const != "desync" {
			continue
		}
		found = true
		mode, ok := variant.Properties.Get("mode")
		if !ok || len(mode.Enum) != len(option.DesyncModes) {
			t.Fatal("desync mode enum missing")
		}
		fooling, ok := variant.Properties.Get("fooling")
		if !ok || len(fooling.Enum) != len(option.DesyncFoolingMethods) {
			t.Fatal("desync fooling enum missing")
		}
		for i, value := range fooling.Enum {
			if value != option.DesyncFoolingMethods[i] {
				t.Fatalf("schema fooling value %v differs from strategy contract", value)
			}
		}
		tlsrec, ok := variant.Properties.Get("tlsrec_first")
		if !ok || tlsrec.Type != "boolean" {
			t.Fatal("missing tlsrec_first schema")
		}
		split, ok := variant.Properties.Get("split_pos")
		if !ok || split.Type != "string" {
			t.Fatal("missing record split_pos schema")
		}
		if _, ok = variant.Properties.Get("routing_mark"); !ok {
			t.Fatal("desync dialer schema missing")
		}
		for _, key := range []string{"SocketControl", "SocketControlOwnsBind"} {
			if _, ok = variant.Properties.Get(key); ok {
				t.Fatalf("internal socket option %s exposed in schema", key)
			}
		}
	}
	if !found {
		t.Fatal("desync not registered in schema")
	}
}
