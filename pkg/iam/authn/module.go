package authn

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	authnEvent "openiam/internal/authn/adapter/inbound/event"
	authnStrategy "openiam/internal/authn/adapter/outbound/strategy"
	authnApp "openiam/internal/authn/application"
	shared "openiam/internal/shared/domain"
)

// Config carries the static, environment-shaped configuration of the
// authn module. Optional providers (SIWE, WebAuthn) stay disabled when
// their fields are zero so the module can be embedded in deployments
// that only use, say, password auth.
type Config struct {
	JWTSecret      string
	JWTIssuer      string
	AccessTokenTTL time.Duration
	SessionTTL     time.Duration

	// AllowInsecureJWTSecret bypasses the production-grade checks on
	// JWTSecret. Intended for tests / local hacking only; never set
	// this to true in a real deployment.
	AllowInsecureJWTSecret bool

	SIWEDomain        string
	WebAuthnRPID      string
	WebAuthnRPName    string
	WebAuthnRPOrigins []string
}

// InsecureJWTSecretSentinel is the placeholder JWTSecret that the
// shipped example config uses; the boot path refuses to start when
// JWTSecret matches it (unless AllowInsecureJWTSecret is set).
const InsecureJWTSecretSentinel = "change-me-in-production"

// MinJWTSecretLength is the minimum acceptable length for a production
// HMAC-SHA256 JWT secret. RFC 7518 §3.2 requires the key to be at
// least as long as the hash output (256 bits / 32 bytes); we enforce
// that as a byte length on the raw secret.
const MinJWTSecretLength = 32

// ErrInsecureJWTSecret is returned by New when the configured JWT
// secret is empty, equal to InsecureJWTSecretSentinel, or shorter than
// MinJWTSecretLength, and the caller did not explicitly opt into
// insecure mode via Config.AllowInsecureJWTSecret.
var ErrInsecureJWTSecret = fmt.Errorf("authn: jwt secret is missing, default, or shorter than %d bytes — set IAM_JWT_SECRET to a strong random value (or AllowInsecureJWTSecret for non-production)", MinJWTSecretLength)

// ErrMissingPort is returned by New when Deps is missing a non-optional
// port. The error wraps the missing port name so the caller can fix
// their wiring without having to read the source.
var ErrMissingPort = errors.New("authn: missing required port")

// Deps carries the outbound infrastructure ports the authn module
// needs. Ports the module can run without (RateLimiter, AppDirectory,
// Logger) are explicitly optional — pass NoOp* to make the
// "intentionally disabled" intent visible in deployment configs.
type Deps struct {
	Credentials   CredentialStore
	Sessions      SessionStore
	Challenges    ChallengeStore
	EventBus      shared.EventBus
	Identity      IdentityIntegration
	TokenProvider TokenProvider

	// AppDirectory is required by SIWE and WebAuthn (which need to
	// resolve an application's owning tenant before provisioning
	// external users). Password-only deployments may pass nil; New
	// then refuses to enable SIWE/WebAuthn even if Config asks for
	// them, so a misconfiguration fails loudly.
	AppDirectory AppDirectory

	// RateLimiter throttles login traffic. Optional: when nil the
	// module installs NoOpRateLimiter and never blocks. Passing
	// NoOpRateLimiter explicitly is recommended in production
	// configs to make the intent visible to readers.
	RateLimiter RateLimiter

	// Logger is optional; falls back to slog.Default().
	Logger *slog.Logger
}

// Module is the assembled authn bounded context returned by New.
// Service is the public surface used by transports; the other fields
// expose the few infrastructure handles host code occasionally needs
// (e.g. transport middleware that wants to verify a bearer token
// without importing the JWT package directly).
type Module struct {
	Service       Service
	TokenProvider TokenProvider
}

// New assembles the authn module from cfg and deps. Returns
// ErrMissingPort wrapped with the name of the first missing
// dependency, ErrInsecureJWTSecret when the secret fails the safety
// check, or any error returned by the underlying authn factory.
func New(cfg Config, deps Deps) (*Module, error) {
	if deps.Credentials == nil {
		return nil, fmt.Errorf("%w: Credentials", ErrMissingPort)
	}
	if deps.Sessions == nil {
		return nil, fmt.Errorf("%w: Sessions", ErrMissingPort)
	}
	if deps.Challenges == nil {
		return nil, fmt.Errorf("%w: Challenges", ErrMissingPort)
	}
	if deps.EventBus == nil {
		return nil, fmt.Errorf("%w: EventBus", ErrMissingPort)
	}
	if deps.Identity == nil {
		return nil, fmt.Errorf("%w: Identity", ErrMissingPort)
	}
	if deps.TokenProvider == nil {
		return nil, fmt.Errorf("%w: TokenProvider", ErrMissingPort)
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

	// Login throttling lives in the application layer so any
	// transport (REST, gRPC, …) gets the same protection. nil keeps
	// the package default (NoopRateLimiter); pass an explicit Noop
	// to make the "intentionally disabled" case obvious in
	// deployment configs.
	if deps.RateLimiter != nil {
		opts = append(opts, authnApp.WithLoginRateLimit(deps.RateLimiter, 0, 0))
	}

	if cfg.SIWEDomain != "" {
		if deps.AppDirectory == nil {
			return nil, fmt.Errorf("authn: SIWE requires Deps.AppDirectory to resolve tenant from app id")
		}
		opts = append(opts, authnApp.WithSIWEAuth(
			authnStrategy.SIWEConfig{Domain: cfg.SIWEDomain},
			deps.Credentials, id, deps.Challenges, deps.AppDirectory,
		))
	}

	if cfg.WebAuthnRPID != "" && len(cfg.WebAuthnRPOrigins) > 0 {
		if deps.AppDirectory == nil {
			return nil, fmt.Errorf("authn: WebAuthn requires Deps.AppDirectory to resolve tenant from app id")
		}
		opts = append(opts, authnApp.WithWebAuthnAuth(
			authnStrategy.WebAuthnConfig{
				RPID:          cfg.WebAuthnRPID,
				RPDisplayName: cfg.WebAuthnRPName,
				RPOrigins:     cfg.WebAuthnRPOrigins,
			},
			deps.Credentials, id, deps.Challenges, deps.AppDirectory,
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

	return &Module{
		Service:       svc,
		TokenProvider: deps.TokenProvider,
	}, nil
}

// validateJWTSecret enforces the production-grade safety floor on the
// HMAC-SHA256 signing secret. Empty, the well-known placeholder, or
// shorter than MinJWTSecretLength all fail closed.
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

// Compile-time assertion: the internal application service implements
// the public Service surface. If a method is added or renamed on either
// side the build breaks here, instead of at the first transport call.
var _ Service = (*authnApp.AuthnAppService)(nil)
