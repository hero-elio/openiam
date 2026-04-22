package tenant

import (
	"context"
	"errors"

	shared "openiam/internal/shared/domain"
	tenantDomain "openiam/internal/tenant/domain"
	"openiam/pkg/iam/authn"
	"openiam/pkg/iam/identity"
)

// AppDirectoryFor adapts a tenant Service into the authn.AppDirectory
// port, used by SIWE / WebAuthn strategies to discover an app's
// owning tenant before provisioning external users.
func AppDirectoryFor(svc Service) authn.AppDirectory {
	return tenantAuthnBridge{svc: svc}
}

// ScopeValidatorFor adapts a tenant Service into the
// identity.ScopeValidator port, used by RegisterUser /
// RegisterExternalUser to refuse rows pointing at unknown
// tenants/applications.
func ScopeValidatorFor(svc Service) identity.ScopeValidator {
	return tenantIdentityBridge{svc: svc}
}

// SubjectExistenceFor exposes the tenant module as the app-side half
// of authz.SubjectExistence. Compose with identity.SubjectExistenceFor
// via authz.ComposeSubjectExistence to get the full port.
//
// The returned interface intentionally only declares the AppExists
// method — the user side belongs to identity. The authz composer
// merges however many partials the host wires.
type SubjectExistencePartial interface {
	AppExists(ctx context.Context, id AppID) (bool, error)
}

func SubjectExistenceFor(svc Service) SubjectExistencePartial {
	return tenantAuthzBridge{svc: svc}
}

// tenantAuthnBridge satisfies authn.AppDirectory.
type tenantAuthnBridge struct {
	svc Service
}

func (b tenantAuthnBridge) TenantOf(ctx context.Context, appID shared.AppID) (shared.TenantID, error) {
	if appID.IsEmpty() {
		return "", shared.ErrInvalidInput
	}
	app, err := b.svc.GetApplication(ctx, &GetApplicationQuery{AppID: appID.String()})
	if err != nil {
		if errors.Is(err, tenantDomain.ErrAppNotFound) {
			return "", shared.ErrNotFound
		}
		return "", err
	}
	return shared.TenantID(app.TenantID), nil
}

// tenantIdentityBridge satisfies identity.ScopeValidator. Translates
// tenant-domain not-found errors into shared.ErrNotFound so identity
// can handle them uniformly.
type tenantIdentityBridge struct {
	svc Service
}

func (b tenantIdentityBridge) EnsureTenant(ctx context.Context, tenantID shared.TenantID) error {
	if tenantID.IsEmpty() {
		return shared.ErrInvalidInput
	}
	if _, err := b.svc.GetTenant(ctx, &GetTenantQuery{TenantID: tenantID.String()}); err != nil {
		if errors.Is(err, tenantDomain.ErrTenantNotFound) {
			return shared.ErrNotFound
		}
		return err
	}
	return nil
}

func (b tenantIdentityBridge) EnsureApplication(ctx context.Context, tenantID shared.TenantID, appID shared.AppID) error {
	if appID.IsEmpty() {
		return shared.ErrInvalidInput
	}
	app, err := b.svc.GetApplication(ctx, &GetApplicationQuery{AppID: appID.String()})
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

// tenantAuthzBridge satisfies the app-side of authz.SubjectExistence.
type tenantAuthzBridge struct {
	svc Service
}

func (b tenantAuthzBridge) AppExists(ctx context.Context, id AppID) (bool, error) {
	return b.svc.AppExists(ctx, id)
}
