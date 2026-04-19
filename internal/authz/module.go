package authz

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"

	authzEvent "openiam/internal/authz/adapter/inbound/event"
	authzRest "openiam/internal/authz/adapter/inbound/rest"
	authzPersistence "openiam/internal/authz/adapter/outbound/persistence"
	authzApp "openiam/internal/authz/application"
	authzQuery "openiam/internal/authz/application/query"
	authzDomain "openiam/internal/authz/domain"

	sharedAuth "openiam/internal/shared/auth"
	shared "openiam/internal/shared/domain"
)

type Authorizer struct {
	Service *authzApp.AuthzAppService
	Handler *authzRest.Handler
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
		appID := claims.AppID
		if appID == "" {
			appID = "default"
		}
		result, err := svc.CheckPermission(ctx, &authzQuery.CheckPermission{
			UserID:   claims.UserID,
			AppID:    appID,
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

	handler := authzRest.NewHandler(svc, checker)

	sub := authzEvent.NewSubscriber(roleRepo, permDefRepo, bus, txMgr)
	if err := sub.Register(); err != nil {
		return nil, fmt.Errorf("register authz event subscriber: %w", err)
	}

	return &Authorizer{
		Service: svc,
		Handler: handler,
		Checker: checker,
	}, nil
}
