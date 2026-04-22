package authn

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	authnEvent "openiam/internal/authn/adapter/inbound/event"
	authnRest "openiam/internal/authn/adapter/inbound/rest"
	authnStrategy "openiam/internal/authn/adapter/outbound/strategy"
	authnApp "openiam/internal/authn/application"
	authnDomain "openiam/internal/authn/domain"

	identityApp "openiam/internal/identity/application"
	identityCommand "openiam/internal/identity/application/command"
	identityQuery "openiam/internal/identity/application/query"

	shared "openiam/internal/shared/domain"
)

type Config struct {
	JWTSecret      string
	JWTIssuer      string
	AccessTokenTTL time.Duration
	SessionTTL     time.Duration

	SIWEDomain        string
	WebAuthnRPID      string
	WebAuthnRPName    string
	WebAuthnRPOrigins []string
}

type Authenticator struct {
	Service       *authnApp.AuthnAppService
	Handler       *authnRest.Handler
	TokenProvider authnDomain.TokenProvider
}

// IdentityIntegration is the outbound port to the identity bounded context
// for registration and external-identity provisioning during sign-in.
type IdentityIntegration interface {
	authnDomain.UserRegistrar
	authnDomain.ExternalLoginIdentity
}

// AuthenticatorDeps wires infrastructure implementations into the authn module.
// Construct adapters (Postgres, Redis, JWT, identity bridge) in the composition root.
type AuthenticatorDeps struct {
	Credentials   authnDomain.CredentialRepository
	Sessions      authnDomain.SessionRepository
	Challenges    authnDomain.ChallengeStore
	EventBus      shared.EventBus
	Identity      IdentityIntegration
	TokenProvider authnDomain.TokenProvider
	Logger        *slog.Logger
}

// NewIdentityBridge adapts identity application services to authn domain ports.
func NewIdentityBridge(svc *identityApp.IdentityService) IdentityIntegration {
	return &identityBridge{svc: svc}
}

// NewAuthenticator assembles the authn bounded context from configuration and ports.
// It does not reference concrete databases or caches — those belong in the composition root.
func NewAuthenticator(cfg Config, deps AuthenticatorDeps) (*Authenticator, error) {
	if deps.Credentials == nil || deps.Sessions == nil || deps.Challenges == nil {
		return nil, fmt.Errorf("authn: credentials, sessions, and challenges repositories are required")
	}
	if deps.EventBus == nil {
		return nil, fmt.Errorf("authn: event bus is required")
	}
	if deps.Identity == nil {
		return nil, fmt.Errorf("authn: identity integration is required")
	}
	if deps.TokenProvider == nil {
		return nil, fmt.Errorf("authn: token provider is required")
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}

	id := deps.Identity
	opts := []authnApp.Option{
		authnApp.WithPasswordAuth(deps.Credentials, id),
		authnApp.WithRegistrar(id),
		authnApp.WithUserInfoProvider(id),
	}

	if cfg.SIWEDomain != "" {
		opts = append(opts, authnApp.WithSIWEAuth(
			authnStrategy.SIWEConfig{Domain: cfg.SIWEDomain},
			deps.Credentials, id, deps.Challenges,
		))
	}

	if cfg.WebAuthnRPID != "" && len(cfg.WebAuthnRPOrigins) > 0 {
		opts = append(opts, authnApp.WithWebAuthnAuth(
			authnStrategy.WebAuthnConfig{
				RPID:          cfg.WebAuthnRPID,
				RPDisplayName: cfg.WebAuthnRPName,
				RPOrigins:     cfg.WebAuthnRPOrigins,
			},
			deps.Credentials, id, deps.Challenges,
		))
	}

	sessionTTL := cfg.SessionTTL
	if sessionTTL == 0 {
		sessionTTL = 7 * 24 * time.Hour
	}

	svc, err := authnApp.NewAuthnAppService(
		deps.Sessions, deps.TokenProvider, deps.EventBus, sessionTTL, logger,
		opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("init authn service: %w", err)
	}

	sub := authnEvent.NewSubscriber(deps.Credentials, logger)
	if err := sub.Register(deps.EventBus); err != nil {
		return nil, fmt.Errorf("register authn event subscriber: %w", err)
	}

	handler := authnRest.NewHandler(svc, deps.TokenProvider)

	return &Authenticator{
		Service:       svc,
		Handler:       handler,
		TokenProvider: deps.TokenProvider,
	}, nil
}

// identityBridge adapts the identity service to the authn domain interfaces
// (UserRegistrar, ExternalLoginIdentity).
type identityBridge struct {
	svc *identityApp.IdentityService
}

func (a *identityBridge) GetUserInfo(ctx context.Context, userID shared.UserID) (*authnDomain.UserInfo, error) {
	dto, err := a.svc.GetUser(ctx, &identityQuery.GetUser{UserID: userID.String()})
	if err != nil {
		return nil, err
	}
	return &authnDomain.UserInfo{
		UserID:   userID,
		TenantID: shared.TenantID(dto.TenantID),
		Status:   dto.Status,
	}, nil
}

func (a *identityBridge) Register(ctx context.Context, req *authnDomain.RegisterRequest) (string, error) {
	uid, err := a.svc.RegisterUser(ctx, &identityCommand.RegisterUser{
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

func (a *identityBridge) ProvisionExternalUser(ctx context.Context, req *authnDomain.ProvisionExternalUserRequest) (*authnDomain.UserInfo, error) {
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = "default"
	}

	uid, err := a.svc.RegisterExternalUser(ctx, &identityCommand.RegisterExternalUser{
		AppID:             req.AppID.String(),
		TenantID:          string(tenantID),
		Provider:          req.Provider,
		CredentialSubject: req.CredentialSubject,
		PublicKey:         req.PublicKey,
	})
	if err != nil {
		return nil, err
	}

	return &authnDomain.UserInfo{
		UserID:   uid,
		TenantID: tenantID,
		Status:   "active",
	}, nil
}
