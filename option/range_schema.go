package option

import (
	"reflect"

	"github.com/sagernet/sing-box/schema"
)

// DescribeSchema includes every JSON representation accepted by Range.
func (Range[T]) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	number, err := builder.Describe(reflect.TypeFor[T]())
	if err != nil {
		return nil, err
	}
	object := schema.StrictObject()
	object.Properties.Put("from", number)
	object.Properties.Put("to", number)
	return schema.AnyOf(number, schema.StringNode(), object), nil
}
