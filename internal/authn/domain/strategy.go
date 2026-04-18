package domain

import (
	"context"
	"encoding/json"
	"time"

	shared "openiam/internal/shared/domain"
)

type CredentialType string

const (
	CredentialPassword CredentialType = "password"
	CredentialSIWE     CredentialType = "siwe"
	CredentialWebAuthn CredentialType = "webauthn"
	CredentialSMS      CredentialType = "sms"
	CredentialOAuth2   CredentialType = "oauth2"
)

type AuthnRequest struct {
	AppID  shared.AppID
	Params json.RawMessage
}

type AuthnStrategy interface {
	Type() CredentialType
	Authenticate(ctx context.Context, req *AuthnRequest) (*AuthnResult, error)
}

// BindableStrategy can verify a cryptographic proof and return the verified subject
// without performing credential lookup. Used for credential binding flows.
type BindableStrategy interface {
	AuthnStrategy
	VerifyAndBind(ctx context.Context, req *AuthnRequest, userID shared.UserID) error
}

type ChallengeableStrategy interface {
	AuthnStrategy
	Challenge(ctx context.Context, req *ChallengeRequest) (*ChallengeResponse, error)
}

type AuthnResult struct {
	UserID   shared.UserID
	TenantID shared.TenantID
	Subject  string
	IsNew    bool
}

type ChallengeRequest struct {
	AppID  shared.AppID
	Params json.RawMessage
}

type ChallengeResponse struct {
	ChallengeID string         `json:"challenge_id"`
	Provider    string         `json:"provider"`
	Data        map[string]any `json:"data"`
	ExpiresAt   time.Time      `json:"expires_at"`
}

type ChallengeStore interface {
	Save(ctx context.Context, challengeID string, data []byte, ttl time.Duration) error
	Get(ctx context.Context, challengeID string) ([]byte, error)
	Delete(ctx context.Context, challengeID string) error
}

type UserInfoProvider interface {
	GetUserInfo(ctx context.Context, userID shared.UserID) (*UserInfo, error)
}

type RegisterRequest struct {
	AppID    string
	Provider string
	Email    string
	Password string
	TenantID string
	Metadata map[string]string
}

type UserRegistrar interface {
	Register(ctx context.Context, req *RegisterRequest) (userID string, err error)
}

// ExternalIdentityProvider creates a user from an external credential subject
// (e.g. CAIP-10 address for SIWE, base64url credential ID for WebAuthn)
// and returns the new user's identity. Called during first-time external login.
type ExternalIdentityProvider interface {
	EnsureExternalUser(ctx context.Context, req *EnsureExternalUserRequest) (*UserInfo, error)
}

type EnsureExternalUserRequest struct {
	AppID             shared.AppID
	TenantID          shared.TenantID
	Provider          string
	CredentialSubject string
	PublicKey         string
}

// CredentialBinder creates a new credential for an already-authenticated user.
type CredentialBinder interface {
	BindCredential(ctx context.Context, req *BindCredentialRequest) error
}

type BindCredentialRequest struct {
	UserID            shared.UserID
	AppID             shared.AppID
	CredentialType    CredentialType
	Provider          string
	CredentialSubject string
	PublicKey         string
}

type UserInfo struct {
	UserID   shared.UserID
	TenantID shared.TenantID
	Status   string
}
