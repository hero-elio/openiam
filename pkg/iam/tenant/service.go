package tenant

import (
	"context"

	tenantApp "openiam/internal/tenant/application"
)

// Public DTOs returned by Service. Definitions live in
// internal/tenant/application; the aliases here are what SDK
// consumers depend on.
type (
	TenantDTO               = tenantApp.TenantDTO
	ApplicationDTO          = tenantApp.ApplicationDTO
	CreateApplicationResult = tenantApp.CreateApplicationResult
)

// Service is the protocol-agnostic surface of the tenant module.
type Service interface {
	CreateTenant(ctx context.Context, cmd *CreateTenantCommand) (TenantID, error)
	GetTenant(ctx context.Context, q *GetTenantQuery) (*TenantDTO, error)

	CreateApplication(ctx context.Context, cmd *CreateApplicationCommand) (*CreateApplicationResult, error)
	GetApplication(ctx context.Context, q *GetApplicationQuery) (*ApplicationDTO, error)
	ListApplications(ctx context.Context, q *ListApplicationsQuery) ([]*ApplicationDTO, error)
	UpdateApplication(ctx context.Context, cmd *UpdateApplicationCommand) error

	// AppExists is the cheap "is this app id known?" probe other
	// modules (most importantly authz) consult before recording
	// grants.
	AppExists(ctx context.Context, id AppID) (bool, error)
}
