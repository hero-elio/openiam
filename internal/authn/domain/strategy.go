package domain

import (
	"context"

	shared "openiam/internal/shared/domain"
)

type CredentialType string

const (
	CredentialPassword CredentialType = "password"
	CredentialSIWE     CredentialType = "siwe"
	CredentialOAuth2   CredentialType = "oauth2"
)

type AuthnRequest struct {
	AppID  shared.AppID
	Params map[string]string
}

type AuthnStrategy interface {
	Type() CredentialType
	Authenticate(ctx context.Context, req *AuthnRequest) (*AuthnResult, error)
}

type AuthnResult struct {
	UserID   shared.UserID
	TenantID shared.TenantID
	Subject  string
	IsNew    bool
}

type UserInfoProvider interface {
	GetUserInfo(ctx context.Context, userID shared.UserID) (*UserInfo, error)
}

type UserInfo struct {
	UserID   shared.UserID
	TenantID shared.TenantID
	Status   string
}
