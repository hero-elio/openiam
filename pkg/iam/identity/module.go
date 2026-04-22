package identity

import (
	"errors"
	"fmt"

	identityApp "openiam/internal/identity/application"
	shared "openiam/internal/shared/domain"
)

// Config carries the static, environment-shaped configuration of the
// identity module. Today there are no required tunables, but the shape
// is here so the Builder can stay symmetric across modules and so
// future settings (password policy, tenant defaults, …) have a home.
type Config struct{}

// Deps wires the outbound infrastructure ports the identity module
// needs. UserStore is mandatory; Scopes is optional and primarily
// used to refuse user creation against unknown tenants/applications.
type Deps struct {
	Users     UserStore
	EventBus  shared.EventBus
	TxManager shared.TxManager

	// Scopes optionally validates that the tenant / application a
	// user is being attached to actually exists. When nil, only
	// format validation is performed; callers wiring identity
	// alongside the tenant module should pass
	// tenant.ScopeValidatorFor(tenantModule).
	Scopes ScopeValidator
}

// Module is the assembled identity bounded context returned by New.
type Module struct {
	Service Service
}

// ErrMissingPort is returned by New when Deps is missing a
// non-optional port. The error wraps the missing port name so the
// caller can fix wiring without reading the source.
var ErrMissingPort = errors.New("identity: missing required port")

// New assembles the identity module from cfg and deps.
func New(_ Config, deps Deps) (*Module, error) {
	if deps.Users == nil {
		return nil, fmt.Errorf("%w: Users", ErrMissingPort)
	}
	if deps.EventBus == nil {
		return nil, fmt.Errorf("%w: EventBus", ErrMissingPort)
	}
	if deps.TxManager == nil {
		return nil, fmt.Errorf("%w: TxManager", ErrMissingPort)
	}

	var opts []identityApp.Option
	if deps.Scopes != nil {
		opts = append(opts, identityApp.WithScopeValidator(deps.Scopes))
	}
	svc := identityApp.NewIdentityService(deps.Users, deps.EventBus, deps.TxManager, opts...)
	return &Module{Service: svc}, nil
}

// Compile-time assertion: the internal identity service implements the
// public Service surface.
var _ Service = (*identityApp.IdentityService)(nil)
