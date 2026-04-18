package application

import (
	"context"

	shared "openiam/internal/shared/domain"
	"openiam/internal/shared/infra/persistence"

	"openiam/internal/identity/application/command"
	"openiam/internal/identity/application/query"
	"openiam/internal/identity/domain"
)

type UserDTO struct {
	ID          string
	Email       string
	DisplayName string
	Status      string
	TenantID    string
	CreatedAt   string
}

type IdentityService struct {
	userRepo  domain.UserRepository
	eventBus  shared.EventBus
	txManager *persistence.TxManager
}

func NewIdentityService(userRepo domain.UserRepository, eventBus shared.EventBus, txManager *persistence.TxManager) *IdentityService {
	return &IdentityService{
		userRepo:  userRepo,
		eventBus:  eventBus,
		txManager: txManager,
	}
}

func (s *IdentityService) RegisterUser(ctx context.Context, cmd *command.RegisterUser) (shared.UserID, error) {
	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		return "", err
	}

	tenantID := shared.TenantID(cmd.TenantID)
	appID := shared.AppID(cmd.AppID)

	exists, err := s.userRepo.ExistsByEmail(ctx, tenantID, email)
	if err != nil {
		return "", err
	}
	if exists {
		return "", shared.ErrEmailAlreadyTaken
	}

	provider := cmd.Provider
	if provider == "" {
		provider = "password"
	}

	user, err := domain.NewUser(email, cmd.Password, tenantID, appID, provider)
	if err != nil {
		return "", err
	}

	if err := s.txManager.Execute(ctx, func(txCtx context.Context) error {
		if err := s.userRepo.Save(txCtx, user); err != nil {
			return err
		}
		return s.eventBus.Publish(txCtx, user.PullEvents()...)
	}); err != nil {
		return "", err
	}

	return user.ID, nil
}

func (s *IdentityService) GetUser(ctx context.Context, q *query.GetUser) (*UserDTO, error) {
	user, err := s.userRepo.FindByID(ctx, shared.UserID(q.UserID))
	if err != nil {
		return nil, err
	}
	return toUserDTO(user), nil
}

func (s *IdentityService) ChangePassword(ctx context.Context, cmd *command.ChangePassword) error {
	user, err := s.userRepo.FindByID(ctx, shared.UserID(cmd.UserID))
	if err != nil {
		return err
	}

	if err := user.ChangePassword(cmd.OldPassword, cmd.NewPassword); err != nil {
		return err
	}

	return s.txManager.Execute(ctx, func(txCtx context.Context) error {
		if err := s.userRepo.Save(txCtx, user); err != nil {
			return err
		}
		return s.eventBus.Publish(txCtx, user.PullEvents()...)
	})
}

func (s *IdentityService) UpdateProfile(ctx context.Context, cmd *command.UpdateProfile) error {
	user, err := s.userRepo.FindByID(ctx, shared.UserID(cmd.UserID))
	if err != nil {
		return err
	}

	user.UpdateProfile(domain.Profile{
		DisplayName: cmd.DisplayName,
		AvatarURL:   cmd.AvatarURL,
	})

	return s.userRepo.Save(ctx, user)
}

func (s *IdentityService) FindByEmail(ctx context.Context, tenantID shared.TenantID, emailStr string) (*UserDTO, error) {
	email, err := domain.NewEmail(emailStr)
	if err != nil {
		return nil, err
	}
	user, err := s.userRepo.FindByEmail(ctx, tenantID, email)
	if err != nil {
		return nil, err
	}
	return toUserDTO(user), nil
}

func toUserDTO(u *domain.User) *UserDTO {
	return &UserDTO{
		ID:          u.ID.String(),
		Email:       u.Email.String(),
		DisplayName: u.Profile.DisplayName,
		Status:      string(u.Status),
		TenantID:    u.TenantID.String(),
		CreatedAt:   u.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}
