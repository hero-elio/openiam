package authn

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	authnEvent "openiam/internal/authn/adapter/inbound/event"
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

	// AllowInsecureJWTSecret bypasses the production-grade checks on
	// JWTSecret. Intended for tests / local hacking only; never set this
	// to true in a real deployment.
	AllowInsecureJWTSecret bool

	SIWEDomain        string
	WebAuthnRPID      string
	WebAuthnRPName    string
	WebAuthnRPOrigins []string
}

// InsecureJWTSecretSentinel is the placeholder value shipped in the
// example config. The boot path refuses to start when JWTSecret matches
// it (unless AllowInsecureJWTSecret is set), so a forgotten override in
// production fails loudly instead of silently using a known-public key.
const InsecureJWTSecretSentinel = "change-me-in-production"

// MinJWTSecretLength is the minimum acceptable length for a production
// HMAC-SHA256 JWT secret. RFC 7518 §3.2 requires the key to be at least
// as long as the hash output (256 bits / 32 bytes); we enforce that as
// a byte length on the raw secret.
const MinJWTSecretLength = 32

// ErrInsecureJWTSecret signals that the configured JWT secret is empty,
// equals the publicly known placeholder, or is shorter than the minimum
// safe length, and the caller did not explicitly opt into insecure mode.
var ErrInsecureJWTSecret = fmt.Errorf("authn: jwt secret is missing, default, or shorter than %d bytes — set IAM_JWT_SECRET to a strong random value (or AllowInsecureJWTSecret for non-production)", MinJWTSecretLength)

// Authenticator bundles the wired authn application service and the
// token provider needed by transport-layer middleware. The HTTP handler
// no longer lives here — transport adapters in pkg/iam/transport/rest
// consume Service directly.
type Authenticator struct {
	Service       *authnApp.AuthnAppService
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
	Apps          authnDomain.AppDirectory
	TokenProvider authnDomain.TokenProvider
	// RateLimiter throttles login traffic. Optional: when nil the
	// service installs a NoopRateLimiter and never blocks.
	RateLimiter authnDomain.RateLimiter
	Logger      *slog.Logger
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
	if !cfg.AllowInsecureJWTSecret {
		if err := validateJWTSecret(cfg.JWTSecret); err != nil {
			return nil, err
		}
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.AllowInsecureJWTSecret {
		logger.Warn("authn: AllowInsecureJWTSecret is enabled — do not run this configuration in production")
	}

	id := deps.Identity
	opts := []authnApp.Option{
		authnApp.WithPasswordAuth(deps.Credentials, id),
		authnApp.WithRegistrar(id),
		authnApp.WithUserInfoProvider(id),
	}

	// Login throttling lives in the application layer so any transport
	// (REST, gRPC, …) gets the same protection. nil keeps the package
	// default (NoopRateLimiter); pass an explicit Noop to make the
	// "intentionally disabled" case obvious in deployment configs.
	if deps.RateLimiter != nil {
		opts = append(opts, authnApp.WithLoginRateLimit(deps.RateLimiter, 0, 0))
	}

	if cfg.SIWEDomain != "" {
		if deps.Apps == nil {
			return nil, fmt.Errorf("authn: SIWE requires AppDirectory in deps to resolve tenant from app id")
		}
		opts = append(opts, authnApp.WithSIWEAuth(
			authnStrategy.SIWEConfig{Domain: cfg.SIWEDomain},
			deps.Credentials, id, deps.Challenges, deps.Apps,
		))
	}

	if cfg.WebAuthnRPID != "" && len(cfg.WebAuthnRPOrigins) > 0 {
		if deps.Apps == nil {
			return nil, fmt.Errorf("authn: WebAuthn requires AppDirectory in deps to resolve tenant from app id")
		}
		opts = append(opts, authnApp.WithWebAuthnAuth(
			authnStrategy.WebAuthnConfig{
				RPID:          cfg.WebAuthnRPID,
				RPDisplayName: cfg.WebAuthnRPName,
				RPOrigins:     cfg.WebAuthnRPOrigins,
			},
			deps.Credentials, id, deps.Challenges, deps.Apps,
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

	return &Authenticator{
		Service:       svc,
		TokenProvider: deps.TokenProvider,
	}, nil
}

func validateJWTSecret(secret string) error {
	if secret == "" {
		return ErrInsecureJWTSecret
	}
	if secret == InsecureJWTSecretSentinel {
		return ErrInsecureJWTSecret
	}
	if len(secret) < MinJWTSecretLength {
		return ErrInsecureJWTSecret
	}
	return nil
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
	if req.TenantID.IsEmpty() {
		return nil, fmt.Errorf("authn: ProvisionExternalUser called without TenantID — strategies must resolve the tenant via AppDirectory")
	}

	uid, err := a.svc.RegisterExternalUser(ctx, &identityCommand.RegisterExternalUser{
		AppID:             req.AppID.String(),
		TenantID:          string(req.TenantID),
		Provider:          req.Provider,
		CredentialSubject: req.CredentialSubject,
		PublicKey:         req.PublicKey,
	})
	if err != nil {
		return nil, err
	}

	return &authnDomain.UserInfo{
		UserID:   uid,
		TenantID: req.TenantID,
		Status:   "active",
	}, nil
}
