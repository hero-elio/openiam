package event

import (
	"context"
	"log/slog"
	"time"

	shared "openiam/internal/shared/domain"

	"openiam/internal/authz/domain"
)

const defaultRoleName = "member"

type userRegisteredPayload interface {
	shared.DomainEvent
	GetUserID() shared.UserID
	GetAppID() shared.AppID
	GetTenantID() shared.TenantID
}

type applicationCreatedPayload interface {
	shared.DomainEvent
	GetAppID() shared.AppID
	GetTenantID() shared.TenantID
	GetCreatedBy() shared.UserID
}

type Subscriber struct {
	roleRepo    domain.RoleRepository
	permDefRepo domain.PermissionDefinitionRepository
	eventBus    shared.EventBus
}

func NewSubscriber(roleRepo domain.RoleRepository, permDefRepo domain.PermissionDefinitionRepository, eventBus shared.EventBus) *Subscriber {
	return &Subscriber{roleRepo: roleRepo, permDefRepo: permDefRepo, eventBus: eventBus}
}

func (s *Subscriber) Register() error {
	if err := s.eventBus.Subscribe("user.registered", s.onUserRegistered); err != nil {
		return err
	}
	return s.eventBus.Subscribe("application.created", s.onApplicationCreated)
}

func (s *Subscriber) onUserRegistered(ctx context.Context, evt shared.DomainEvent) error {
	payload, ok := evt.(userRegisteredPayload)
	if !ok {
		slog.Warn("unexpected event type for user.registered", "aggregate_id", evt.AggregateID())
		return nil
	}

	userID := payload.GetUserID()
	tenantID := payload.GetTenantID()
	appID := payload.GetAppID()

	roles, err := s.roleRepo.ListByApp(ctx, appID)
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
		AppID:      appID,
		RoleID:     memberRole.ID,
		TenantID:   tenantID,
		AssignedAt: time.Now(),
	}

	if err = s.roleRepo.SaveUserAppRole(ctx, uar); err != nil {
		slog.Error("failed to auto-assign default role", "user_id", userID.String(), "error", err)
		return err
	}

	slog.Info("auto-assigned default role", "user_id", userID.String(), "role_id", memberRole.ID.String())
	return nil
}

func (s *Subscriber) onApplicationCreated(ctx context.Context, evt shared.DomainEvent) error {
	payload, ok := evt.(applicationCreatedPayload)
	if !ok {
		slog.Warn("unexpected event type for application.created", "aggregate_id", evt.AggregateID())
		return nil
	}

	appID := payload.GetAppID()
	tenantID := payload.GetTenantID()
	createdBy := payload.GetCreatedBy()

	slog.Info("seeding system roles for new application", "app_id", appID.String())

	type seedRole struct {
		name        string
		description string
		permissions []domain.Permission
	}

	seeds := []seedRole{
		{
			name:        "super_admin",
			description: "Super administrator with all permissions",
			permissions: []domain.Permission{domain.NewPermission("*", "*")},
		},
		{
			name:        "admin",
			description: "Administrator with user and role management permissions",
			permissions: []domain.Permission{
				domain.NewPermission(domain.ResourceUsers, domain.ActionRead),
				domain.NewPermission(domain.ResourceUsers, domain.ActionUpdate),
				domain.NewPermission(domain.ResourceRoles, domain.ActionAll),
				domain.NewPermission(domain.ResourcePermissions, domain.ActionCheck),
			},
		},
		{
			name:        "member",
			description: "Basic member role (auto-assigned on registration)",
			permissions: nil,
		},
	}

	var superAdminRole *domain.Role
	for _, seed := range seeds {
		role := domain.NewSystemRole(appID, tenantID, seed.name, seed.description)
		for _, perm := range seed.permissions {
			_ = role.GrantPermission(perm)
		}

		if err := s.roleRepo.Save(ctx, role); err != nil {
			slog.Error("failed to seed system role", "role", seed.name, "error", err)
			return err
		}

		if seed.name == "super_admin" {
			superAdminRole = role
		}
	}

	if !createdBy.IsEmpty() && superAdminRole != nil {
		uar := &domain.UserAppRole{
			UserID:     createdBy,
			AppID:      appID,
			RoleID:     superAdminRole.ID,
			TenantID:   tenantID,
			AssignedAt: time.Now(),
		}
		if err := s.roleRepo.SaveUserAppRole(ctx, uar); err != nil {
			slog.Error("failed to assign super_admin to creator", "user_id", createdBy.String(), "error", err)
			return err
		}
		slog.Info("assigned super_admin role to app creator", "user_id", createdBy.String(), "app_id", appID.String())
	}

	for _, bp := range domain.BuiltinPermissions {
		pd := &domain.PermissionDefinition{
			AppID:       appID,
			Resource:    bp.Resource,
			Action:      bp.Action,
			Description: bp.Description,
			IsBuiltin:   true,
			CreatedAt:   time.Now(),
		}
		if err := s.permDefRepo.Upsert(ctx, pd); err != nil {
			slog.Error("failed to sync builtin permission", "resource", bp.Resource, "action", bp.Action, "error", err)
			return err
		}
	}

	slog.Info("seeded system roles and synced builtin permissions", "app_id", appID.String())
	return nil
}
