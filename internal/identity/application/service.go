package application

import (
	"context"
	"errors"
	"time"

	shared "openiam/internal/shared/domain"

	"openiam/internal/identity/application/command"
	"openiam/internal/identity/application/query"
	"openiam/internal/identity/domain"
)

type UserDTO struct {
	ID          string
	Email       string
	DisplayName string
	AvatarURL   string
	Status      string
	TenantID    string
	CreatedAt   string
}

type IdentityService struct {
	userRepo  domain.UserRepository
	eventBus  shared.EventBus
	txManager shared.TxManager
	scopes    domain.ScopeValidator
}

type Option func(*IdentityService)

// WithScopeValidator wires in a tenant/application existence check so
// RegisterUser / RegisterExternalUser refuse to create rows pointing at
// tenants or apps that do not exist. When omitted (e.g. in tests) the
// service falls back to format-only validation.
func WithScopeValidator(v domain.ScopeValidator) Option {
	return func(s *IdentityService) {
		s.scopes = v
	}
}

func NewIdentityService(
	userRepo domain.UserRepository,
	eventBus shared.EventBus,
	txManager shared.TxManager,
	opts ...Option,
) *IdentityService {
	s := &IdentityService{
		userRepo:  userRepo,
		eventBus:  eventBus,
		txManager: txManager,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *IdentityService) RegisterUser(ctx context.Context, cmd *command.RegisterUser) (shared.UserID, error) {
	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		return "", err
	}

	tenantID := shared.TenantID(cmd.TenantID)
	appID := shared.AppID(cmd.AppID)
	if tenantID.IsEmpty() || appID.IsEmpty() {
		return "", shared.ErrInvalidInput
	}
	if err := s.ensureScope(ctx, tenantID, appID); err != nil {
		return "", err
	}

	exists, err := s.userRepo.ExistsByEmail(ctx, tenantID, email)
	if err != nil {
		return "", err
	}
	if exists {
		return "", domain.ErrEmailAlreadyTaken
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

func (s *IdentityService) RegisterExternalUser(ctx context.Context, cmd *command.RegisterExternalUser) (shared.UserID, error) {
	tenantID := shared.TenantID(cmd.TenantID)
	appID := shared.AppID(cmd.AppID)
	if tenantID.IsEmpty() || appID.IsEmpty() {
		return "", shared.ErrInvalidInput
	}
	if cmd.Provider == "" || cmd.CredentialSubject == "" {
		return "", shared.ErrInvalidInput
	}
	if err := s.ensureScope(ctx, tenantID, appID); err != nil {
		return "", err
	}

	user := domain.NewExternalUser(tenantID, appID, cmd.Provider, cmd.CredentialSubject, cmd.PublicKey)

	// External identity dedup: the placeholder email encodes
	// sha256(provider:credential_subject), and the users table holds a
	// UNIQUE(tenant_id, email). That gives provider-scoped uniqueness for
	// free, so we only need to (1) do the inevitable existence check and
	// the write inside the same transaction so concurrent registrations
	// converge on a single row, and (2) translate a unique-violation back
	// into "return the existing user" for idempotency.
	var resolvedID shared.UserID
	err := s.txManager.Execute(ctx, func(txCtx context.Context) error {
		if existing, err := s.userRepo.FindByEmail(txCtx, tenantID, user.Email); err == nil {
			resolvedID = existing.ID
			return nil
		} else if !errors.Is(err, domain.ErrUserNotFound) {
			return err
		}

		if saveErr := s.userRepo.Save(txCtx, user); saveErr != nil {
			if errors.Is(saveErr, domain.ErrEmailAlreadyTaken) {
				existing, lookupErr := s.userRepo.FindByEmail(txCtx, tenantID, user.Email)
				if lookupErr != nil {
					return lookupErr
				}
				resolvedID = existing.ID
				return nil
			}
			return saveErr
		}
		resolvedID = user.ID
		return s.eventBus.Publish(txCtx, user.PullEvents()...)
	})
	if err != nil {
		return "", err
	}
	return resolvedID, nil
}

func (s *IdentityService) ListUsers(ctx context.Context, q *query.ListUsers) ([]*UserDTO, error) {
	filter := domain.ListUsersFilter{}
	if q != nil {
		filter.TenantID = shared.TenantID(q.TenantID)
		filter.EmailLike = q.EmailLike
		filter.Limit = q.Limit
		filter.Offset = q.Offset
	}
	users, err := s.userRepo.List(ctx, filter)
	if err != nil {
		return nil, err
	}
	dtos := make([]*UserDTO, 0, len(users))
	for _, u := range users {
		dtos = append(dtos, toUserDTO(u))
	}
	return dtos, nil
}

func (s *IdentityService) GetUser(ctx context.Context, q *query.GetUser) (*UserDTO, error) {
	user, err := s.userRepo.FindByID(ctx, shared.UserID(q.UserID))
	if err != nil {
		return nil, err
	}
	return toUserDTO(user), nil
}

// UserExists is a thin wrapper around the user repository for other
// contexts (e.g. authz) that need a "is this a real user?" pre-check
// without growing a transitive dependency on the identity domain.
// Returns (false, nil) for a clean miss; only surfaces other errors.
func (s *IdentityService) UserExists(ctx context.Context, id shared.UserID) (bool, error) {
	if id == "" {
		return false, nil
	}
	_, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
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

	return s.txManager.Execute(ctx, func(txCtx context.Context) error {
		if err := s.userRepo.Save(txCtx, user); err != nil {
			return err
		}
		return s.eventBus.Publish(txCtx, user.PullEvents()...)
	})
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

func (s *IdentityService) ensureScope(ctx context.Context, tenantID shared.TenantID, appID shared.AppID) error {
	if s.scopes == nil {
		return nil
	}
	if err := s.scopes.EnsureTenant(ctx, tenantID); err != nil {
		return err
	}
	return s.scopes.EnsureApplication(ctx, tenantID, appID)
}

func toUserDTO(u *domain.User) *UserDTO {
	return &UserDTO{
		ID:          u.ID.String(),
		Email:       u.Email.String(),
		DisplayName: u.Profile.DisplayName,
		AvatarURL:   u.Profile.AvatarURL,
		Status:      string(u.Status),
		TenantID:    u.TenantID.String(),
		CreatedAt:   u.CreatedAt.Format(time.RFC3339),
	}
}
