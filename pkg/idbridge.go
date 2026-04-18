package iam

import (
	"context"
	authnDomain "openiam/internal/authn/domain"
	identityApp "openiam/internal/identity/application"
	identityCommand "openiam/internal/identity/application/command"
	identityQuery "openiam/internal/identity/application/query"
	shared "openiam/internal/shared/domain"
)

// identityBridgeAdapter implements authnDomain.UserInfoProvider and authnDomain.UserRegistrar
// by delegating to the identity bounded context.
type identityBridgeAdapter struct {
	svc *identityApp.IdentityService
}

func (a *identityBridgeAdapter) GetUserInfo(ctx context.Context, userID shared.UserID) (*authnDomain.UserInfo, error) {
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

func (a *identityBridgeAdapter) Register(ctx context.Context, req *authnDomain.RegisterRequest) (string, error) {
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
