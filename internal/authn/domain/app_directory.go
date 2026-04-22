package domain

import (
	"context"

	shared "openiam/internal/shared/domain"
)

// AppDirectory resolves application metadata that the authn context
// needs at sign-in time but does not own. The primary use case is
// finding the owning tenant of an application so external-identity
// strategies (SIWE, WebAuthn) can provision new users into the right
// tenant instead of hard-coding "default".
//
// Implementations live in adapters that bridge to the tenant context.
type AppDirectory interface {
	TenantOf(ctx context.Context, appID shared.AppID) (shared.TenantID, error)
}
