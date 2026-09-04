package interceptors

import (
	"context"
	"fmt"
	"testing"

	"github.com/arkade-os/arkd/pkg/macaroons"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

const testMethod = "/emulator.v1.EmulatorService/SubmitTx"

// rejectingValidator stands in for a configured macaroon service that refuses
// an unauthenticated request.
type rejectingValidator struct {
	gotMethod string
}

func (v *rejectingValidator) ValidateMacaroon(
	_ context.Context, _ []bakery.Op, fullMethod string,
) error {
	v.gotMethod = fullMethod
	return fmt.Errorf("cannot get macaroon from context")
}

// acceptingValidator stands in for a configured macaroon service presented with
// a valid macaroon.
type acceptingValidator struct{}

func (acceptingValidator) ValidateMacaroon(
	_ context.Context, _ []bakery.Op, _ string,
) error {
	return nil
}

func unaryInfo() *grpc.UnaryServerInfo {
	return &grpc.UnaryServerInfo{FullMethod: testMethod}
}

func okHandler(called *bool) grpc.UnaryHandler {
	return func(context.Context, any) (any, error) {
		*called = true
		return "ok", nil
	}
}

// TestUnaryMacaroonAuthRejectsWhenConfigured is the core security assertion:
// with a macaroon service configured, a request that fails validation never
// reaches the signing handler.
func TestUnaryMacaroonAuthRejectsWhenConfigured(t *testing.T) {
	v := &rejectingValidator{}
	called := false

	_, err := unaryMacaroonAuth(v)(
		context.Background(), nil, unaryInfo(), okHandler(&called),
	)

	if err == nil {
		t.Fatal("expected unauthenticated request to be rejected")
	}
	if got := status.Code(err); got != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %s: %s", got, err)
	}
	if called {
		t.Fatal("handler was reached despite failed macaroon validation")
	}
	if v.gotMethod != testMethod {
		t.Fatalf("validator got method %q, want %q", v.gotMethod, testMethod)
	}
	// The underlying reason must not leak to the caller.
	if msg := status.Convert(err).Message(); msg != "invalid or missing macaroon" {
		t.Fatalf("unexpected error message %q", msg)
	}
}

// TestUnaryMacaroonAuthAllowsWhenValid checks the gate is not simply closed.
func TestUnaryMacaroonAuthAllowsWhenValid(t *testing.T) {
	called := false

	resp, err := unaryMacaroonAuth(acceptingValidator{})(
		context.Background(), nil, unaryInfo(), okHandler(&called),
	)
	if err != nil {
		t.Fatalf("valid macaroon was rejected: %s", err)
	}
	if !called || resp != "ok" {
		t.Fatal("handler was not reached for a valid macaroon")
	}
}

// TestUnaryMacaroonAuthAllowsWhenUnconfigured pins the no-regression case:
// deployments that configure no macaroon service keep serving requests.
func TestUnaryMacaroonAuthAllowsWhenUnconfigured(t *testing.T) {
	called := false

	if _, err := unaryMacaroonAuth(validator(nil))(
		context.Background(), nil, unaryInfo(), okHandler(&called),
	); err != nil {
		t.Fatalf("request was rejected with no macaroon service: %s", err)
	}
	if !called {
		t.Fatal("handler was not reached with no macaroon service")
	}
}

// TestValidatorMapsNilServiceToNilInterface guards the typed-nil trap: a nil
// *macaroons.Service must not become a non-nil interface, which would make
// validateMacaroon call through a nil pointer.
func TestValidatorMapsNilServiceToNilInterface(t *testing.T) {
	var svc *macaroons.Service
	if v := validator(svc); v != nil {
		t.Fatal("nil macaroon service produced a non-nil validator")
	}
}

// TestStreamMacaroonAuthRejectsWhenConfigured mirrors the unary assertion for
// the stream path.
func TestStreamMacaroonAuthRejectsWhenConfigured(t *testing.T) {
	called := false
	handler := func(any, grpc.ServerStream) error {
		called = true
		return nil
	}

	err := streamMacaroonAuth(&rejectingValidator{})(
		nil, stubStream{}, &grpc.StreamServerInfo{FullMethod: testMethod}, handler,
	)

	if got := status.Code(err); got != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %s: %v", got, err)
	}
	if called {
		t.Fatal("stream handler was reached despite failed macaroon validation")
	}
}

type stubStream struct{ grpc.ServerStream }

func (stubStream) Context() context.Context { return context.Background() }
