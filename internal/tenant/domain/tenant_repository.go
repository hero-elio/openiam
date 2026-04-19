package domain

import (
	"context"

	shared "openiam/internal/shared/domain"
)

type TenantRepository interface {
	SaveTenant(ctx context.Context, t *Tenant) error
	FindTenantByID(ctx context.Context, id shared.TenantID) (*Tenant, error)

	SaveApplication(ctx context.Context, app *Application) error
	FindApplicationByID(ctx context.Context, id shared.AppID) (*Application, error)
	FindApplicationByClientID(ctx context.Context, clientID string) (*Application, error)
	ListApplicationsByTenant(ctx context.Context, tenantID shared.TenantID) ([]*Application, error)
}
