package authn

import (
	"errors"
	"fmt"
	"log/slog"

	"openiam/internal/authn"
	authnApp "openiam/internal/authn/application"
	shared "openiam/internal/shared/domain"
)

// Config carries the static, environment-shaped configuration of the
// authn module. Optional providers (SIWE, WebAuthn) stay disabled when
// their fields are zero so the module can be embedded in deployments
// that only use, say, password auth.
type Config = authn.Config

// InsecureJWTSecretSentinel is the placeholder JWTSecret that the
// shipped example config uses; the boot path refuses to start when
// JWTSecret matches it (unless AllowInsecureJWTSecret is set).
const InsecureJWTSecretSentinel = authn.InsecureJWTSecretSentinel

// MinJWTSecretLength is the minimum acceptable length for a production
// HMAC-SHA256 JWT secret.
const MinJWTSecretLength = authn.MinJWTSecretLength

// ErrInsecureJWTSecret is returned by New when the configured JWT secret
// is empty, equal to InsecureJWTSecretSentinel, or shorter than
// MinJWTSecretLength, and the caller did not explicitly opt into
// insecure mode via Config.AllowInsecureJWTSecret.
var ErrInsecureJWTSecret = authn.ErrInsecureJWTSecret

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

	authMod, err := authn.NewAuthenticator(cfg, authn.AuthenticatorDeps{
		Credentials:   deps.Credentials,
		Sessions:      deps.Sessions,
		Challenges:    deps.Challenges,
		EventBus:      deps.EventBus,
		Identity:      deps.Identity,
		Apps:          deps.AppDirectory,
		TokenProvider: deps.TokenProvider,
		RateLimiter:   deps.RateLimiter,
		Logger:        deps.Logger,
	})
	if err != nil {
		return nil, err
	}
	return &Module{
		Service:       authMod.Service,
		TokenProvider: authMod.TokenProvider,
	}, nil
}

// Compile-time assertion: the internal application service implements
// the public Service surface. If a method is added or renamed on either
// side the build breaks here, instead of at the first transport call.
var _ Service = (*authnApp.AuthnAppService)(nil)
