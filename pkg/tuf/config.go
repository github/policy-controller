package tuf

import (
	"context"
	"time"

	"knative.dev/pkg/controller"
)

type trustrootResyncPeriodKey struct{}

func ToContext(ctx context.Context, duration time.Duration) context.Context {
	return context.WithValue(ctx, trustrootResyncPeriodKey{}, duration)
}

// FromContextOrDefaults returns a stored trustrootResyncPeriod if attached.
// If not found, it returns a default duration
func FromContextOrDefaults(ctx context.Context) time.Duration {
	x, ok := ctx.Value(trustrootResyncPeriodKey{}).(time.Duration)
	if ok {
		return x
	}
	return controller.DefaultResyncPeriod
}
