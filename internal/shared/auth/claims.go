package auth

import "context"

type claimsKey struct{}

type Claims struct {
	UserID    string
	TenantID  string
	AppID     string
	SessionID string
	Roles     []string
}

func ClaimsFromContext(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(claimsKey{}).(Claims)
	return c, ok
}

func ContextWithClaims(ctx context.Context, c Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, c)
}

// Checker verifies whether the caller (identified via context Claims) is
// permitted to perform the given action on the given resource.
// Returns nil if allowed, a non-nil error otherwise.
// This is protocol-agnostic — HTTP handlers, gRPC interceptors, etc. can
// all depend on the same Checker.
type Checker func(ctx context.Context, resource, action string) error
