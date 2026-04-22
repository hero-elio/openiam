package identity

import (
	"github.com/jmoiron/sqlx"

	shared "openiam/internal/shared/domain"

	identityPersistence "openiam/internal/identity/adapter/outbound/persistence"
	"openiam/internal/identity/application"
	identityDomain "openiam/internal/identity/domain"
)

// Registry bundles the wired identity application service. The HTTP
// handler no longer lives here — transport adapters in
// pkg/iam/transport/rest consume Service directly.
type Registry struct {
	Service *application.IdentityService
}

func NewRegistry(
	db *sqlx.DB,
	bus shared.EventBus,
	txMgr shared.TxManager,
	scopes identityDomain.ScopeValidator,
) *Registry {
	userRepo := identityPersistence.NewPostgresUserRepository(db)

	var opts []application.Option
	if scopes != nil {
		opts = append(opts, application.WithScopeValidator(scopes))
	}
	svc := application.NewIdentityService(userRepo, bus, txMgr, opts...)

	return &Registry{Service: svc}
}
