package strategy

import (
	"context"
	"encoding/json"

	"github.com/alexedwards/argon2id"

	"openiam/internal/authn/domain"
	shared "openiam/internal/shared/domain"
)

type passwordParams struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type PasswordStrategy struct {
	credRepo     domain.CredentialRepository
	userProvider domain.UserInfoProvider
}

func NewPasswordStrategy(credRepo domain.CredentialRepository, userProvider domain.UserInfoProvider) *PasswordStrategy {
	return &PasswordStrategy{
		credRepo:     credRepo,
		userProvider: userProvider,
	}
}

func (s *PasswordStrategy) Type() domain.CredentialType {
	return domain.CredentialPassword
}

func (s *PasswordStrategy) Authenticate(ctx context.Context, req *domain.AuthnRequest) (*domain.AuthnResult, error) {
	var p passwordParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return nil, shared.ErrInvalidCredential
	}
	if p.Email == "" || p.Password == "" {
		return nil, shared.ErrInvalidCredential
	}

	cred, err := s.credRepo.FindBySubjectAndType(ctx, p.Email, req.AppID, domain.CredentialPassword)
	if err != nil {
		return nil, err
	}

	if cred.Secret == nil {
		return nil, shared.ErrInvalidCredential
	}

	match, err := argon2id.ComparePasswordAndHash(p.Password, *cred.Secret)
	if err != nil {
		return nil, err
	}
	if !match {
		return nil, shared.ErrInvalidPassword
	}

	info, err := s.userProvider.GetUserInfo(ctx, cred.UserID)
	if err != nil {
		return nil, err
	}

	switch info.Status {
	case "disabled":
		return nil, shared.ErrUserDisabled
	case "locked":
		return nil, shared.ErrUserLocked
	case "active":
	default:
		return nil, shared.ErrUnauthorized
	}

	cred.MarkUsed()
	_ = s.credRepo.Update(ctx, cred)

	return &domain.AuthnResult{
		UserID:   cred.UserID,
		TenantID: info.TenantID,
		Subject:  cred.CredentialSubject,
	}, nil
}
