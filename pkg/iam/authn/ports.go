package authn

import (
	"openiam/internal/authn/domain"
)

// Outbound ports the authn module needs from the host application.
//
// SDK consumers wire these via Deps when calling New. Adapters for
// Postgres, Redis, JWT, and a memory backend live under
// pkg/iam/adapters/* — most users will never have to implement these
// by hand. The interfaces stay aliased to internal/authn/domain for
// now so the existing repository implementations satisfy them
// unchanged.
type (
	CredentialStore = domain.CredentialRepository
	SessionStore    = domain.SessionRepository
	ChallengeStore  = domain.ChallengeStore
	TokenProvider   = domain.TokenProvider
	RateLimiter     = domain.RateLimiter
	AppDirectory    = domain.AppDirectory

	UserRegistrar            = domain.UserRegistrar
	UserInfoProvider         = domain.UserInfoProvider
	ExternalIdentityProvider = domain.ExternalIdentityProvider
	ExternalLoginIdentity    = domain.ExternalLoginIdentity
	CredentialBinder         = domain.CredentialBinder
)

// IdentityIntegration is the composite port the authn module needs
// from the identity bounded context: it must be able to provision
// users on first sign-in (UserRegistrar / ExternalIdentityProvider)
// and to look up their current status on every request
// (UserInfoProvider).
//
// SDK consumers usually obtain an implementation by calling
// pkg/iam/identity.IntegrationFor(identityModule). A custom identity
// store can satisfy this interface directly.
type IdentityIntegration interface {
	UserRegistrar
	ExternalLoginIdentity
}
