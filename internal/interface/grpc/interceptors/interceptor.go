package interceptors

import (
	"context"

	"github.com/arkade-os/arkd/pkg/macaroons"
	middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UnaryInterceptor returns the unary interceptor
func UnaryInterceptor(svc *macaroons.Service) grpc.ServerOption {
	return grpc.UnaryInterceptor(middleware.ChainUnaryServer(
		unaryLogger,
		unaryMacaroonAuth(validator(svc)),
	))
}

// StreamInterceptor returns the stream interceptor with a logrus log
func StreamInterceptor(svc *macaroons.Service) grpc.ServerOption {
	return grpc.StreamInterceptor(middleware.ChainStreamServer(
		streamLogger,
		streamMacaroonAuth(validator(svc)),
	))
}

// validator converts the macaroon service to the validating interface, mapping
// a nil service to a nil interface rather than a non-nil interface holding a
// nil pointer.
func validator(svc *macaroons.Service) macaroons.MacaroonValidator {
	if svc == nil {
		return nil
	}
	return svc
}

func unaryMacaroonAuth(v macaroons.MacaroonValidator) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context, req any,
		info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
	) (any, error) {
		if err := validateMacaroon(ctx, v, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func streamMacaroonAuth(v macaroons.MacaroonValidator) grpc.StreamServerInterceptor {
	return func(
		srv any, stream grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler,
	) error {
		if err := validateMacaroon(stream.Context(), v, info.FullMethod); err != nil {
			return err
		}
		return handler(srv, stream)
	}
}

// validateMacaroon rejects any request that does not carry a macaroon valid for
// the called method. It is a no-op when no macaroon service is configured, so
// deployments that run without auth keep working; once one is configured it
// fails closed. The reason for a rejection is deliberately not echoed back to
// the caller.
func validateMacaroon(
	ctx context.Context, v macaroons.MacaroonValidator, fullMethod string,
) error {
	if v == nil {
		return nil
	}

	if err := v.ValidateMacaroon(ctx, nil, fullMethod); err != nil {
		return status.Error(codes.Unauthenticated, "invalid or missing macaroon")
	}

	return nil
}
