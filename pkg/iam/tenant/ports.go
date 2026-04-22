package tenant

import (
	"openiam/internal/tenant/domain"
)

// Outbound persistence ports the tenant module uses. Postgres
// implementations are bundled in pkg/iam/adapters/postgres.
type (
	TenantStore      = domain.TenantRepository
	ApplicationStore = domain.ApplicationRepository
)
