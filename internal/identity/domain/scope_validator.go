package domain

import (
	"context"

	shared "openiam/internal/shared/domain"
)

// ScopeValidator lets the identity context confirm that the tenant /
// application a user is being attached to actually exist before the user is
// persisted. Implementations live outside this package (composition root
// adapts the tenant context). Keeping it as a port avoids a hard import
// from identity into tenant.
//
// Returning shared.ErrNotFound communicates "the scope is unknown"; any
// other error is propagated as-is.
type ScopeValidator interface {
	EnsureTenant(ctx context.Context, tenantID shared.TenantID) error
	EnsureApplication(ctx context.Context, tenantID shared.TenantID, appID shared.AppID) error
}
