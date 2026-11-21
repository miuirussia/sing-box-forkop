package urltest

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
)

type contextKeyIsUnifiedDelay struct{}

type contextKeyOutbound struct{}

// OutboundFromContext returns the member being probed, so a DNS detour can
// bootstrap through it without waiting for the probe it is serving.
func OutboundFromContext(ctx context.Context) adapter.Outbound {
	outbound, _ := ctx.Value(contextKeyOutbound{}).(adapter.Outbound)
	return outbound
}

func ContextWithIsUnifiedDelay(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKeyIsUnifiedDelay{}, true)
}

func IsUnifiedDelayFromContext(ctx context.Context) bool {
	return ctx.Value(contextKeyIsUnifiedDelay{}) != nil
}
