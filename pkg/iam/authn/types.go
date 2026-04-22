// Package authn is the public SDK surface for the IAM authentication
// module. SDK users that want to embed IAM should depend on this package
// (and pkg/iam/transport/rest for HTTP wiring) instead of poking into
// internal/authn/*.
//
// Phase 2 of the SDK refactor brings the public surface up cleanly while
// leaving the actual implementation in internal/authn. Most types here
// are aliases that pin a stable name to an internal definition; the
// internal location stays the source of truth so the existing
// adapter / strategy code keeps compiling unchanged.
package authn

import (
	"openiam/internal/authn/domain"
)

// Domain types re-exported for SDK consumers.
//
// Aliases keep the internal package as the source of truth so existing
// repository / strategy code does not need to be rewritten before
// Phase 5 lifts the canonical definitions up here.
type (
	Credential     = domain.Credential
	CredentialType = domain.CredentialType
	Session        = domain.Session
	TokenClaims    = domain.TokenClaims
	TokenPair      = domain.TokenPair
	ClientInfo     = domain.ClientInfo

	AuthnRequest         = domain.AuthnRequest
	AuthnResult          = domain.AuthnResult
	AuthnStrategy        = domain.AuthnStrategy
	BindableStrategy     = domain.BindableStrategy
	ChallengeableStrategy = domain.ChallengeableStrategy
	SubjectExtractor     = domain.SubjectExtractor

	ChallengeRequest  = domain.ChallengeRequest
	ChallengeResponse = domain.ChallengeResponse

	UserInfo                     = domain.UserInfo
	RegisterRequest              = domain.RegisterRequest
	ProvisionExternalUserRequest = domain.ProvisionExternalUserRequest
	BindCredentialRequest        = domain.BindCredentialRequest

	UserLoggedInEvent   = domain.UserLoggedInEvent
	UserLoggedOutEvent  = domain.UserLoggedOutEvent
	TokenRefreshedEvent = domain.TokenRefreshedEvent

	RateLimitedError = domain.RateLimitedError
)

// Credential type constants re-exported for convenience.
const (
	CredentialPassword = domain.CredentialPassword
	CredentialSIWE     = domain.CredentialSIWE
	CredentialWebAuthn = domain.CredentialWebAuthn
	CredentialSMS      = domain.CredentialSMS
	CredentialOAuth2   = domain.CredentialOAuth2
)

// Domain event names re-exported for SDK subscribers.
const (
	EventUserLoggedIn   = domain.EventUserLoggedIn
	EventUserLoggedOut  = domain.EventUserLoggedOut
	EventTokenRefreshed = domain.EventTokenRefreshed
)

// Domain sentinel errors re-exported so SDK callers can errors.Is
// against them without importing internal packages.
var (
	ErrCredentialNotFound      = domain.ErrCredentialNotFound
	ErrCredentialAlreadyExists = domain.ErrCredentialAlreadyExists
	ErrInvalidCredential       = domain.ErrInvalidCredential
	ErrSessionNotFound         = domain.ErrSessionNotFound
	ErrSessionExpired          = domain.ErrSessionExpired
	ErrInvalidToken            = domain.ErrInvalidToken
	ErrTokenExpired            = domain.ErrTokenExpired
	ErrUnsupportedProvider     = domain.ErrUnsupportedProvider
	ErrChallengeNotSupported   = domain.ErrChallengeNotSupported
	ErrChallengeNotFound       = domain.ErrChallengeNotFound
	ErrChallengeInvalid        = domain.ErrChallengeInvalid
	ErrCredentialAlreadyBound  = domain.ErrCredentialAlreadyBound
)
