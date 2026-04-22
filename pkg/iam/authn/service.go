package authn

import (
	"context"

	authnApp "openiam/internal/authn/application"
	sharedAuth "openiam/internal/shared/auth"
)

// SessionDTO is the public representation of an active user session.
//
// The struct definition lives in internal/authn/application so the
// application service can return the type without back-importing this
// package; the alias here is what SDK consumers should depend on.
type SessionDTO = authnApp.SessionDTO

// Service is the protocol-agnostic surface of the authn module.
//
// Every transport adapter (REST, gRPC, CLI, queue) consumes Service
// instead of the concrete *application.AuthnAppService, so swapping
// transports — or stubbing the whole module out in tests — is just
// a matter of providing a new implementation.
//
// All errors returned here are domain errors (see ErrInvalidToken,
// ErrSessionExpired, *RateLimitedError, …). Transport adapters are
// responsible for translating them to their own status convention.
type Service interface {
	// AuthenticateToken validates a raw bearer token and returns the
	// resolved caller claims. Used by the rest.BearerAuth middleware
	// (and any equivalent gRPC interceptor) on every protected call.
	AuthenticateToken(ctx context.Context, rawToken string) (sharedAuth.Claims, error)

	// Login runs the strategy keyed by cmd.Provider, creates a session,
	// and returns a fresh access/refresh token pair.
	Login(ctx context.Context, cmd *LoginCommand) (*TokenPair, error)

	// Register creates a new user via the wired UserRegistrar and
	// immediately logs them in. Returns the same TokenPair shape as
	// Login.
	Register(ctx context.Context, cmd *RegisterCommand) (*TokenPair, error)

	// Logout revokes the session identified by cmd.SessionID.
	Logout(ctx context.Context, cmd *LogoutCommand) error

	// RefreshToken trades a non-expired refresh token for a new pair
	// and rotates the stored refresh token to defeat replay.
	RefreshToken(ctx context.Context, cmd *RefreshTokenCommand) (*TokenPair, error)

	// BeginChallenge starts a stateful flow (SIWE nonce, WebAuthn
	// assertion, SMS code, …) for providers that need a server-issued
	// challenge before Login.
	BeginChallenge(ctx context.Context, cmd *ChallengeCommand) (*ChallengeResponse, error)

	// BindCredential attaches a new credential (e.g. a WebAuthn key)
	// to an already-authenticated user.
	BindCredential(ctx context.Context, cmd *BindCredentialCommand) error

	// GetSession returns the SessionDTO for a single session id.
	GetSession(ctx context.Context, q *GetSessionQuery) (*SessionDTO, error)

	// ListSessions returns every active session for the given user.
	ListSessions(ctx context.Context, userID string) ([]*SessionDTO, error)
}
