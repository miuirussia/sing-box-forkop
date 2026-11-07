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
