package identity

import (
	"context"
	"fmt"

	"openiam/internal/identity/application/command"
	"openiam/internal/identity/application/query"
	shared "openiam/internal/shared/domain"
	"openiam/pkg/iam/authn"
)

// IntegrationFor adapts an identity Service into the
// authn.IdentityIntegration port (UserRegistrar +
// ExternalIdentityProvider + UserInfoProvider).
//
// Wire it once at composition time and pass the result to authn.New.
// The returned adapter holds only the Service interface, so swapping
// the identity implementation (memory, Postgres, mock) automatically
// reaches the authn module.
func IntegrationFor(svc Service) authn.IdentityIntegration {
	return identityAuthnBridge{svc: svc}
}

// SubjectExistencePartial is the slice of authz.SubjectExistence that
// the identity module owns: "is this user id a real user?". The
// authz module composes one SubjectExistence from however many
// partials the host wires (typically identity + tenant).
//
// The full type is declared in pkg/iam/authz to avoid an authz import
// cycle here.
type SubjectExistencePartial interface {
	UserExists(ctx context.Context, id UserID) (bool, error)
}

// SubjectExistenceFor exposes the identity module as the user-side
// half of authz.SubjectExistence.
func SubjectExistenceFor(svc Service) SubjectExistencePartial {
	return identityAuthzBridge{svc: svc}
}

// identityAuthnBridge satisfies authn.IdentityIntegration by routing
// every call through the public identity Service. We translate
// between the two modules' DTOs here so neither has to know about the
// other's command shapes.
type identityAuthnBridge struct {
	svc Service
}

func (b identityAuthnBridge) GetUserInfo(ctx context.Context, userID shared.UserID) (*authn.UserInfo, error) {
	dto, err := b.svc.GetUser(ctx, &query.GetUser{UserID: userID.String()})
	if err != nil {
		return nil, err
	}
	return &authn.UserInfo{
		UserID:   userID,
		TenantID: shared.TenantID(dto.TenantID),
		Status:   dto.Status,
	}, nil
}

func (b identityAuthnBridge) Register(ctx context.Context, req *authn.RegisterRequest) (string, error) {
	uid, err := b.svc.RegisterUser(ctx, &command.RegisterUser{
		AppID:    req.AppID,
		Provider: req.Provider,
		Email:    req.Email,
		Password: req.Password,
		TenantID: req.TenantID,
	})
	if err != nil {
		return "", err
	}
	return uid.String(), nil
}

func (b identityAuthnBridge) ProvisionExternalUser(ctx context.Context, req *authn.ProvisionExternalUserRequest) (*authn.UserInfo, error) {
	if req.TenantID.IsEmpty() {
		// SIWE/WebAuthn strategies are responsible for resolving the
		// tenant via AppDirectory before reaching here. A missing
		// tenant id at this layer is a wiring bug, not bad user
		// input — fail loudly so the caller fixes their composition
		// root instead of silently provisioning into "default".
		return nil, fmt.Errorf("identity: ProvisionExternalUser called without TenantID — strategies must resolve the tenant via AppDirectory")
	}
	uid, err := b.svc.RegisterExternalUser(ctx, &command.RegisterExternalUser{
		AppID:             req.AppID.String(),
		TenantID:          string(req.TenantID),
		Provider:          req.Provider,
		CredentialSubject: req.CredentialSubject,
		PublicKey:         req.PublicKey,
	})
	if err != nil {
		return nil, err
	}
	return &authn.UserInfo{
		UserID:   uid,
		TenantID: req.TenantID,
		Status:   string(UserStatusActive),
	}, nil
}

// identityAuthzBridge exposes UserExists for the authz subject-existence
// pre-check.
type identityAuthzBridge struct {
	svc Service
}

func (b identityAuthzBridge) UserExists(ctx context.Context, id UserID) (bool, error) {
	return b.svc.UserExists(ctx, id)
}
