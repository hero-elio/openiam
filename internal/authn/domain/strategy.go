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

type UserInfo struct {
	UserID   shared.UserID
	TenantID shared.TenantID
	Status   string
}
