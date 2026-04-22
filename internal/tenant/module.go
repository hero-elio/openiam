package tenant

import (
	"github.com/jmoiron/sqlx"

	shared "openiam/internal/shared/domain"

	tenantPersistence "openiam/internal/tenant/adapter/outbound/persistence"
	tenantApp "openiam/internal/tenant/application"
)

// Manager bundles the wired tenant application service. The HTTP
// handler no longer lives here — transport adapters in
// pkg/iam/transport/rest consume Service directly.
type Manager struct {
	Service *tenantApp.TenantAppService
}

func NewManager(db *sqlx.DB, bus shared.EventBus, txMgr shared.TxManager) *Manager {
	tenantRepo := tenantPersistence.NewPostgresTenantRepository(db)
	appRepo := tenantPersistence.NewPostgresApplicationRepository(db)
	svc := tenantApp.NewTenantAppService(tenantRepo, appRepo, bus, txMgr)

	return &Manager{Service: svc}
}
