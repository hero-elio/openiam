package authz

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"

	authzEvent "openiam/internal/authz/adapter/inbound/event"
	authzPersistence "openiam/internal/authz/adapter/outbound/persistence"
	authzApp "openiam/internal/authz/application"
	authzQuery "openiam/internal/authz/application/query"
	authzDomain "openiam/internal/authz/domain"

	sharedAuth "openiam/internal/shared/auth"
	shared "openiam/internal/shared/domain"
)

// Authorizer bundles the wired authz application service plus the
// derived Checker used by transport-layer middleware. The HTTP handler
// no longer lives here — transport adapters in pkg/iam/transport/rest
// consume Service directly.
type Authorizer struct {
	Service *authzApp.AuthzAppService
	Checker sharedAuth.Checker
}

func NewAuthorizer(db *sqlx.DB, bus shared.EventBus, txMgr shared.TxManager) (*Authorizer, error) {
	roleRepo := authzPersistence.NewPostgresRoleRepository(db)
	resPermRepo := authzPersistence.NewPostgresResourcePermissionRepository(db)
	permDefRepo := authzPersistence.NewPostgresPermissionDefinitionRepository(db)
	enforcer := authzDomain.NewEnforcer(roleRepo, resPermRepo)
	svc := authzApp.NewAuthzAppService(roleRepo, resPermRepo, permDefRepo, enforcer, bus, txMgr)

	checker := sharedAuth.Checker(func(ctx context.Context, resource, action string) error {
		claims, ok := sharedAuth.ClaimsFromContext(ctx)
		if !ok {
			return shared.ErrUnauthorized
		}
		// An empty AppID used to silently fall back to a synthetic "default"
		// app, so any role granted under that name (notably super_admin)
		// could be exercised by tokens that never selected an application.
		// Refuse the request instead — every protected route must run inside
		// an explicit application context.
		if claims.AppID == "" {
			return shared.ErrForbidden
		}
		result, err := svc.CheckPermission(ctx, &authzQuery.CheckPermission{
			UserID:   claims.UserID,
			AppID:    claims.AppID,
			Resource: resource,
			Action:   action,
		})
		if err != nil {
			return err
		}
		if !result.Allowed {
			return shared.ErrForbidden
		}
		return nil
	})

	sub := authzEvent.NewSubscriber(roleRepo, roleRepo, permDefRepo, bus, txMgr)
	if err := sub.Register(); err != nil {
		return nil, fmt.Errorf("register authz event subscriber: %w", err)
	}

	return &Authorizer{
		Service: svc,
		Checker: checker,
	}, nil
}
