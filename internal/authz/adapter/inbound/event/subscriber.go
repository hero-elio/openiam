package event

import (
	"context"
	"log/slog"
	"time"

	shared "openiam/internal/shared/domain"

	"openiam/internal/authz/domain"
	identityDomain "openiam/internal/identity/domain"
)

const defaultRoleName = "member"

type Subscriber struct {
	roleRepo domain.RoleRepository
	eventBus shared.EventBus
}

func NewSubscriber(roleRepo domain.RoleRepository, eventBus shared.EventBus) *Subscriber {
	return &Subscriber{roleRepo: roleRepo, eventBus: eventBus}
}

func (s *Subscriber) Register() error {
	return s.eventBus.Subscribe("user.registered", s.onUserRegistered)
}

func (s *Subscriber) onUserRegistered(ctx context.Context, evt shared.DomainEvent) error {
	reg, ok := evt.(identityDomain.UserRegisteredEvent)
	if !ok {
		slog.Warn("unexpected event type for user.registered")
		return nil
	}

	userID := reg.UserID
	tenantID := reg.TenantID

	roles, err := s.roleRepo.ListByApp(ctx, shared.AppID("default"))
	if err != nil {
		slog.Error("failed to list roles for default app", "error", err)
		return err
	}

	var memberRole *domain.Role
	for _, r := range roles {
		if r.Name == defaultRoleName {
			memberRole = r
			break
		}
	}

	if memberRole == nil {
		slog.Warn("default member role not found, skipping auto-assign", "user_id", userID.String())
		return nil
	}

	uar := &domain.UserAppRole{
		UserID:     userID,
		AppID:      shared.AppID("default"),
		RoleID:     memberRole.ID,
		TenantID:   tenantID,
		AssignedAt: time.Now(),
	}

	if err := s.roleRepo.SaveUserAppRole(ctx, uar); err != nil {
		slog.Error("failed to auto-assign default role", "user_id", userID.String(), "error", err)
		return err
	}

	slog.Info("auto-assigned default role", "user_id", userID.String(), "role_id", memberRole.ID.String())
	return nil
}
