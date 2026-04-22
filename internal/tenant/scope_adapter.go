package tenant

import (
	"context"
	"errors"

	shared "openiam/internal/shared/domain"
	tenantApp "openiam/internal/tenant/application"
	tenantApplicationQuery "openiam/internal/tenant/application/query"
	tenantDomain "openiam/internal/tenant/domain"
)

// ScopeAdapter exposes tenant/application existence checks to other
// bounded contexts (e.g. identity) without leaking domain types. It
// translates tenant-domain not-found errors into shared.ErrNotFound so
// callers can handle them uniformly.
type ScopeAdapter struct {
	svc *tenantApp.TenantAppService
}

func NewScopeAdapter(m *Manager) *ScopeAdapter {
	if m == nil {
		return nil
	}
	return &ScopeAdapter{svc: m.Service}
}

func (a *ScopeAdapter) EnsureTenant(ctx context.Context, tenantID shared.TenantID) error {
	if a == nil || a.svc == nil {
		return nil
	}
	if tenantID.IsEmpty() {
		return shared.ErrInvalidInput
	}
	if _, err := a.svc.GetTenant(ctx, &tenantApplicationQuery.GetTenant{TenantID: tenantID.String()}); err != nil {
		if errors.Is(err, tenantDomain.ErrTenantNotFound) {
			return shared.ErrNotFound
		}
		return err
	}
	return nil
}

func (a *ScopeAdapter) EnsureApplication(ctx context.Context, tenantID shared.TenantID, appID shared.AppID) error {
	if a == nil || a.svc == nil {
		return nil
	}
	if appID.IsEmpty() {
		return shared.ErrInvalidInput
	}
	app, err := a.svc.GetApplication(ctx, &tenantApplicationQuery.GetApplication{AppID: appID.String()})
	if err != nil {
		if errors.Is(err, tenantDomain.ErrAppNotFound) {
			return shared.ErrNotFound
		}
		return err
	}
	if !tenantID.IsEmpty() && app.TenantID != tenantID.String() {
		return shared.ErrForbidden
	}
	return nil
}

// TenantOf implements the authn AppDirectory port. The authn context
// uses this to discover which tenant owns an application during external
// login (SIWE / WebAuthn) so newly provisioned users land in the right
// tenant instead of a hard-coded "default".
func (a *ScopeAdapter) TenantOf(ctx context.Context, appID shared.AppID) (shared.TenantID, error) {
	if a == nil || a.svc == nil {
		return "", shared.ErrNotFound
	}
	if appID.IsEmpty() {
		return "", shared.ErrInvalidInput
	}
	app, err := a.svc.GetApplication(ctx, &tenantApplicationQuery.GetApplication{AppID: appID.String()})
	if err != nil {
		if errors.Is(err, tenantDomain.ErrAppNotFound) {
			return "", shared.ErrNotFound
		}
		return "", err
	}
	return shared.TenantID(app.TenantID), nil
}
