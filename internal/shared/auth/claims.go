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
