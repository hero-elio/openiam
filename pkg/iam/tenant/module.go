package tenant

import (
	"errors"
	"fmt"

	shared "openiam/internal/shared/domain"
	tenantApp "openiam/internal/tenant/application"
)

// Config carries the static configuration of the tenant module. Empty
// today; kept for symmetry with the other module Configs.
type Config struct{}

// Deps wires the outbound infrastructure ports the tenant module
// needs.
type Deps struct {
	Tenants      TenantStore
	Applications ApplicationStore
	EventBus     shared.EventBus
	TxManager    shared.TxManager
}

// Module is the assembled tenant bounded context returned by New.
type Module struct {
	Service Service
}

// ErrMissingPort is returned by New when Deps is missing a
// non-optional port.
var ErrMissingPort = errors.New("tenant: missing required port")

// New assembles the tenant module from cfg and deps.
func New(_ Config, deps Deps) (*Module, error) {
	if deps.Tenants == nil {
		return nil, fmt.Errorf("%w: Tenants", ErrMissingPort)
	}
	if deps.Applications == nil {
		return nil, fmt.Errorf("%w: Applications", ErrMissingPort)
	}
	if deps.EventBus == nil {
		return nil, fmt.Errorf("%w: EventBus", ErrMissingPort)
	}
	if deps.TxManager == nil {
		return nil, fmt.Errorf("%w: TxManager", ErrMissingPort)
	}

	svc := tenantApp.NewTenantAppService(deps.Tenants, deps.Applications, deps.EventBus, deps.TxManager)
	return &Module{Service: svc}, nil
}

// Compile-time assertion: the internal tenant service implements the
// public Service surface.
var _ Service = (*tenantApp.TenantAppService)(nil)
