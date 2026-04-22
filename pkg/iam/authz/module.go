package authz

import (
	"context"
	"errors"
	"fmt"

	authzEvent "openiam/internal/authz/adapter/inbound/event"
	authzApp "openiam/internal/authz/application"
	"openiam/internal/authz/domain"
	sharedAuth "openiam/internal/shared/auth"
	shared "openiam/internal/shared/domain"
)

// Config carries the static configuration of the authz module. Empty
// today; kept for symmetry with the other module Configs and so future
// settings have a home.
type Config struct{}

// Deps wires the outbound infrastructure ports the authz module
// needs. Roles, ResourcePermissions, PermissionDefinitions are
// mandatory; SubjectExistence is optional but strongly recommended in
// real deployments — pass NoOpSubjectExistence to opt out explicitly.
type Deps struct {
	Roles                 RoleStore
	ResourcePermissions   ResourcePermissionStore
	PermissionDefinitions PermissionDefinitionStore
	EventBus              shared.EventBus
	TxManager             shared.TxManager

	// SubjectExistence is consulted by AssignRole and
	// GrantResourcePermission to refuse grants targeting unknown
	// users or apps. Wire ComposeSubjectExistence with the
	// identity/tenant partials, or pass NoOpSubjectExistence to
	// acknowledge the standalone case.
	SubjectExistence SubjectExistence
}

// Module is the assembled authz bounded context returned by New.
//
// Checker is the protocol-agnostic permission-check function transport
// adapters mount as middleware. It honours sharedAuth.Claims pulled
// from the request context.
type Module struct {
	Service Service
	Checker sharedAuth.Checker
}

// ErrMissingPort is returned by New when Deps is missing a
// non-optional port.
var ErrMissingPort = errors.New("authz: missing required port")

// New assembles the authz module from cfg and deps.
func New(_ Config, deps Deps) (*Module, error) {
	if deps.Roles == nil {
		return nil, fmt.Errorf("%w: Roles", ErrMissingPort)
	}
	if deps.ResourcePermissions == nil {
		return nil, fmt.Errorf("%w: ResourcePermissions", ErrMissingPort)
	}
	if deps.PermissionDefinitions == nil {
		return nil, fmt.Errorf("%w: PermissionDefinitions", ErrMissingPort)
	}
	if deps.EventBus == nil {
		return nil, fmt.Errorf("%w: EventBus", ErrMissingPort)
	}
	if deps.TxManager == nil {
		return nil, fmt.Errorf("%w: TxManager", ErrMissingPort)
	}

	enforcer := domain.NewEnforcer(deps.Roles, deps.ResourcePermissions)
	svc := authzApp.NewAuthzAppService(
		deps.Roles, deps.ResourcePermissions, deps.PermissionDefinitions,
		enforcer, deps.EventBus, deps.TxManager,
	)
	if deps.SubjectExistence != nil {
		svc.SetSubjectExistence(deps.SubjectExistence)
	}

	// Wire the cross-context subscribers that auto-assign default
	// roles when a user registers and seed app roles + builtin
	// permissions when a new application is created. Both are
	// no-ops if the publishing modules (identity, tenant) are not
	// installed; the authz module wires them unconditionally so an
	// SDK consumer that adds identity/tenant later automatically
	// picks up the behaviour.
	roleTemplateProvider, ok := deps.Roles.(domain.RoleTemplateProvider)
	if !ok {
		return nil, fmt.Errorf("authz: Deps.Roles must implement domain.RoleTemplateProvider")
	}
	sub := authzEvent.NewSubscriber(deps.Roles, roleTemplateProvider, deps.PermissionDefinitions, deps.EventBus, deps.TxManager)
	if err := sub.Register(); err != nil {
		return nil, fmt.Errorf("authz: register event subscriber: %w", err)
	}

	return &Module{
		Service: svc,
		Checker: BuildChecker(svc),
	}, nil
}

// BuildChecker turns a Service into the protocol-agnostic Checker
// transports mount as middleware. The returned closure pulls Claims
// from the request context (set by rest.BearerAuth or its gRPC
// equivalent) and runs CheckPermission against the resolved app.
//
// An empty AppID short-circuits to ErrForbidden — every protected
// route must run inside an explicit application context, otherwise a
// super-admin role granted under a synthetic "default" app could be
// exercised by tokens that never selected an application.
func BuildChecker(svc Service) sharedAuth.Checker {
	return func(ctx context.Context, resource, action string) error {
		claims, ok := sharedAuth.ClaimsFromContext(ctx)
		if !ok {
			return shared.ErrUnauthorized
		}
		if claims.AppID == "" {
			return shared.ErrForbidden
		}
		result, err := svc.CheckPermission(ctx, &CheckPermissionQuery{
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
	}
}

// Compile-time assertion: the internal authz service implements the
// public Service surface.
var _ Service = (*authzApp.AuthzAppService)(nil)
