// Package sharedauth is the public SDK surface for the cross-context
// auth primitives: Claims (the per-request principal), the
// context helpers ContextWithClaims/ClaimsFromContext, and Checker
// (the protocol-agnostic permission predicate).
//
// These types are deliberately tiny and stable — every transport
// adapter (HTTP, gRPC, CLI) and every permission-aware service depends
// on them, so promoting them to a public package lets SDK consumers
// build their own middleware/interceptors without reaching into
// internal/*.
package sharedauth

import (
	"context"

	internalauth "openiam/internal/shared/auth"
)

// Claims is the authenticated principal carried on the context.
type Claims = internalauth.Claims

// Checker decides whether the principal in ctx may perform action on
// resource. nil means allowed; a non-nil error denies. Build one via
// authz.BuildChecker, or supply a custom one.
type Checker = internalauth.Checker

// ContextWithClaims attaches c to ctx for downstream handlers.
func ContextWithClaims(ctx context.Context, c Claims) context.Context {
	return internalauth.ContextWithClaims(ctx, c)
}

// ClaimsFromContext returns the Claims previously attached via
// ContextWithClaims; ok is false when none are present.
func ClaimsFromContext(ctx context.Context) (Claims, bool) {
	return internalauth.ClaimsFromContext(ctx)
}
