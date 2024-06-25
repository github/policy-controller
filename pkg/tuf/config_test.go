package tuf

import (
	"testing"
	"time"

	"knative.dev/pkg/controller"
	rtesting "knative.dev/pkg/reconciler/testing"
)

func TestContextDuration(t *testing.T) {
	ctx, _ := rtesting.SetupFakeContext(t)

	expected := controller.DefaultResyncPeriod
	actual := FromContextOrDefaults(ctx)
	if expected != actual {
		t.Fatal("Expected the context to store the value and be retrievable")
	}

	expected = time.Hour
	ctx = ToContext(ctx, expected)
	actual = FromContextOrDefaults(ctx)

	if expected != actual {
		t.Fatal("Expected the context to store the value and be retrievable")
	}
}
