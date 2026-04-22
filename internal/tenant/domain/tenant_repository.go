package domain

import (
	"context"

	shared "openiam/internal/shared/domain"
)

type TenantRepository interface {
	Save(ctx context.Context, t *Tenant) error
	FindByID(ctx context.Context, id shared.TenantID) (*Tenant, error)
	List(ctx context.Context, filter ListTenantsFilter) ([]*Tenant, error)
}

// ListTenantsFilter narrows a tenant list query. Limit / Offset are
// the standard paging knobs; Limit <= 0 lets the repository return
// every row (callers should bound it themselves when needed).
type ListTenantsFilter struct {
	Limit  int
	Offset int
}

type ApplicationRepository interface {
	Save(ctx context.Context, app *Application) error
	FindByID(ctx context.Context, id shared.AppID) (*Application, error)
	FindByClientID(ctx context.Context, clientID string) (*Application, error)
	ListByTenant(ctx context.Context, tenantID shared.TenantID) ([]*Application, error)
}
