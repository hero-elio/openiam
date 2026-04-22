// Package rest holds transport adapters that turn the public IAM module
// services into chi routes.
//
// Everything here is HTTP-specific. The package intentionally takes
// dependencies as plain function values (verifiers, checkers) instead of
// importing concrete authn/identity/authz types — that way a custom
// transport (gRPC, CLI, queue worker) can reuse the same checker logic
// without dragging this package along.
package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	sharedAuth "openiam/internal/shared/auth"
)

// TokenVerifier validates a raw bearer token and returns the resolved
// caller claims. It is intentionally protocol-agnostic so the application
// service's AuthenticateToken method (or any equivalent in a custom
// integration) can be passed straight in.
type TokenVerifier func(ctx context.Context, rawToken string) (sharedAuth.Claims, error)

// BearerAuth is HTTP middleware that extracts an "Authorization: Bearer …"
// token, runs it through verify, and stores the resulting Claims on the
// request context for downstream handlers.
//
// Verification is delegated entirely to verify; this package does not know
// what a TokenProvider is and never will. That keeps the middleware reusable
// across token formats (JWT, PASETO, opaque-with-Redis-lookup, …).
func BearerAuth(verify TokenVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := extractBearerToken(r)
			if raw == "" {
				writeMiddlewareError(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
				return
			}
			claims, err := verify(r.Context(), raw)
			if err != nil {
				// We deliberately collapse every verification failure into a
				// generic "invalid token" 401 here. Specific reasons (locked,
				// disabled, expired) belong to the authn application layer
				// and are surfaced via dedicated endpoints / events; leaking
				// them through every protected route would just hand probing
				// information to an attacker.
				writeMiddlewareError(w, http.StatusUnauthorized, "unauthorized", "invalid token")
				return
			}
			next.ServeHTTP(w, r.WithContext(sharedAuth.ContextWithClaims(r.Context(), claims)))
		})
	}
}

// RequirePermission wraps a Checker as chi-compatible middleware. The
// Checker decides; this layer only translates "denied" into HTTP 403.
func RequirePermission(check sharedAuth.Checker, resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := check(r.Context(), resource, action); err != nil {
				writeMiddlewareError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

// writeMiddlewareError keeps the error response shape used by the rest of
// the package. We deliberately do not import any module's writeError —
// middleware predates handlers and must not depend on them.
func writeMiddlewareError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": message})
}
