package option

import (
	"github.com/sagernet/sing-box/schema"
	"reflect"
)

func (o DesyncOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	object := schema.StrictObject()
	if err := builder.FlattenStruct(object, reflect.TypeFor[desyncOptionsJSON]()); err != nil {
		return nil, err
	}
	object.Properties.Put("mode", schema.StringEnum(DesyncModes...))
	object.Properties.Put("preset", schema.StringEnum(DesyncPresets...))
	object.Properties.Put("udp_mode", schema.StringEnum("none", "quic", "stun", "auto"))
	object.Properties.Put("fooling", schema.StringEnum(DesyncFoolingMethods...))
	for key, bounds := range map[string][2]int64{"repeats": {1, 16}, "udp_repeats": {1, 16}, "ttl": {1, 255}, "udp_ttl": {1, 255}, "seqovl": {0, 4096}, "wscale": {0, 14}, "wsize": {0, 65535}, "ipfrag": {0, 65512}, "udplen": {0, 64000}, "quic_repeats": {0, 16}} {
		min, max := bounds[0], uint64(bounds[1])
		object.Properties.Put(key, &schema.Node{Type: "integer", Minimum: &min, Maximum: &max})
	}
	return object, nil
}

func (o DesyncAdaptiveOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	object := schema.StrictObject()
	if err := builder.FlattenStruct(object, reflect.TypeFor[desyncAdaptiveJSON]()); err != nil {
		return nil, err
	}
	for key, bounds := range map[string][2]int64{"max_attempts": {1, 8}, "max_concurrent": {1, 16}, "max_entries": {16, 16384}, "max_buffer": {512, 65536}} {
		min, max := bounds[0], uint64(bounds[1])
		object.Properties.Put(key, &schema.Node{Type: "integer", Minimum: &min, Maximum: &max})
	}
	return object, nil
}
