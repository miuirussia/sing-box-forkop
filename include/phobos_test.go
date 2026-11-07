package include

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/schema"
	"github.com/sagernet/sing/common/json"
)

func TestPhobosConfigurationAndSchema(t *testing.T) {
	ctx := Context(context.Background())
	var options option.Options
	err := json.UnmarshalContext(ctx, []byte(`{"endpoints":[{"type":"phobos","tag":"vpn","address":["10.8.0.2/32"],"private_key":"key","obfuscation":{"key":"test","masking":"MEDIA","obfuscate_bytes":0,"max_dummy":0}}]}`), &options)
	if err != nil {
		t.Fatal(err)
	}
	raw, ok := options.Endpoints[0].Options.(*option.PhobosEndpointOptions)
	if !ok || raw.Obfuscation.ObfuscateBytes == nil || *raw.Obfuscation.ObfuscateBytes != 0 {
		t.Fatalf("unexpected Phobos options: %+v", options.Endpoints[0])
	}
	content, err := schema.Generate(ctx, reflect.TypeFor[option.PhobosEndpointOptions]())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), `"obfuscate_bytes"`) {
		t.Fatal("Phobos obfuscation missing from generated schema")
	}
}
