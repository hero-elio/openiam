package tenant

import (
	"github.com/jmoiron/sqlx"

	sharedAuth "openiam/internal/shared/auth"
	shared "openiam/internal/shared/domain"

	tenantRest "openiam/internal/tenant/adapter/inbound/rest"
	tenantPersistence "openiam/internal/tenant/adapter/outbound/persistence"
	tenantApp "openiam/internal/tenant/application"
)

type Manager struct {
	Service *tenantApp.TenantAppService
	Handler *tenantRest.Handler
}

func NewManager(db *sqlx.DB, bus shared.EventBus, txMgr shared.TxManager, check sharedAuth.Checker) *Manager {
	tenantRepo := tenantPersistence.NewPostgresTenantRepository(db)
	appRepo := tenantPersistence.NewPostgresApplicationRepository(db)
	svc := tenantApp.NewTenantAppService(tenantRepo, appRepo, bus, txMgr)

	var handler *tenantRest.Handler
	if check != nil {
		handler = tenantRest.NewHandler(svc, check)
	}

	return &Manager{
		Service: svc,
		Handler: handler,
	}
}
