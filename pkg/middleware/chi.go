// Package middleware is a backwards-compatibility shim around
// openiam/pkg/iam/transport/rest. New callers should depend on the
// transport package directly; this shim exists only so we can land
// the SDK refactor in stages without breaking the existing wiring.
//
// The shim disappears in Phase 5 of the refactor.
package middleware

import (
	"context"
	"net/http"

	authnDomain "openiam/internal/authn/domain"
	sharedAuth "openiam/internal/shared/auth"
	rest "openiam/pkg/iam/transport/rest"
)

// DefaultMaxRequestBodyBytes mirrors rest.DefaultMaxRequestBodyBytes.
const DefaultMaxRequestBodyBytes = rest.DefaultMaxRequestBodyBytes

// BearerAuth keeps the original TokenProvider-based signature so
// existing call sites compile unchanged. Internally it adapts
// TokenProvider.Validate into the protocol-agnostic TokenVerifier
// signature expected by the transport package.
func BearerAuth(tokenProvider authnDomain.TokenProvider) func(http.Handler) http.Handler {
	verify := func(_ context.Context, raw string) (sharedAuth.Claims, error) {
		tc, err := tokenProvider.Validate(raw)
		if err != nil {
			return sharedAuth.Claims{}, err
		}
		return sharedAuth.Claims{
			UserID:    tc.UserID,
			TenantID:  tc.TenantID,
			AppID:     tc.AppID,
			SessionID: tc.SessionID,
			Roles:     tc.Roles,
		}, nil
	}
	return rest.BearerAuth(verify)
}

// BodyLimit forwards to the transport package.
func BodyLimit(maxBytes int64) func(http.Handler) http.Handler {
	return rest.BodyLimit(maxBytes)
}

// RequirePermission forwards to the transport package.
func RequirePermission(check sharedAuth.Checker, resource, action string) func(http.Handler) http.Handler {
	return rest.RequirePermission(check, resource, action)
}
