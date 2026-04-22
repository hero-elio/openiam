package tenant

import (
	"openiam/internal/tenant/application/command"
	"openiam/internal/tenant/application/query"
)

// Command / query DTOs accepted by Service.
type (
	CreateTenantCommand      = command.CreateTenant
	CreateApplicationCommand = command.CreateApplication
	UpdateApplicationCommand = command.UpdateApplication

	GetTenantQuery        = query.GetTenant
	GetApplicationQuery   = query.GetApplication
	ListApplicationsQuery = query.ListApplications
	ListTenantsQuery      = query.ListTenants
)
