package identity

import (
	"github.com/jmoiron/sqlx"

	sharedAuth "openiam/internal/shared/auth"
	shared "openiam/internal/shared/domain"

	"openiam/internal/identity/adapter/inbound/rest"
	identityPersistence "openiam/internal/identity/adapter/outbound/persistence"
	"openiam/internal/identity/application"
)

type Registry struct {
	Service *application.IdentityService
	Handler *rest.Handler
}

func NewRegistry(db *sqlx.DB, bus shared.EventBus, txMgr shared.TxManager, check sharedAuth.Checker) *Registry {
	userRepo := identityPersistence.NewPostgresUserRepository(db)
	svc := application.NewIdentityService(userRepo, bus, txMgr)

	var handler *rest.Handler
	if check != nil {
		handler = rest.NewHandler(svc, check)
	}

	return &Registry{
		Service: svc,
		Handler: handler,
	}
}
