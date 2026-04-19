package domain

import (
	"context"

	shared "openiam/internal/shared/domain"
)

type UserDomainService struct {
	repo UserRepository
}

func NewUserDomainService(repo UserRepository) *UserDomainService {
	return &UserDomainService{repo: repo}
}

func (s *UserDomainService) CheckEmailUniqueness(ctx context.Context, tenantID shared.TenantID, email Email) error {
	exists, err := s.repo.ExistsByEmail(ctx, tenantID, email)
	if err != nil {
		return err
	}
	if exists {
		return ErrEmailAlreadyTaken
	}
	return nil
}
