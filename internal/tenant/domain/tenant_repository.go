package domain

import (
	"context"

	shared "openiam/internal/shared/domain"
)

type TenantRepository interface {
	Save(ctx context.Context, t *Tenant) error
	FindByID(ctx context.Context, id shared.TenantID) (*Tenant, error)
}

type ApplicationRepository interface {
	Save(ctx context.Context, app *Application) error
	FindByID(ctx context.Context, id shared.AppID) (*Application, error)
	FindByClientID(ctx context.Context, clientID string) (*Application, error)
	ListByTenant(ctx context.Context, tenantID shared.TenantID) ([]*Application, error)
}
