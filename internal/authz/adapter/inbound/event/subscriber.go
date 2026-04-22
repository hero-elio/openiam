package event

import (
	"context"
	"errors"
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
	roleRepo     domain.RoleRepository
	templateProv domain.RoleTemplateProvider
	permDefRepo  domain.PermissionDefinitionRepository
	eventBus     shared.EventBus
	txManager    shared.TxManager
}

func NewSubscriber(
	roleRepo domain.RoleRepository,
	templateProv domain.RoleTemplateProvider,
	permDefRepo domain.PermissionDefinitionRepository,
	eventBus shared.EventBus,
	txManager shared.TxManager,
) *Subscriber {
	return &Subscriber{
		roleRepo:     roleRepo,
		templateProv: templateProv,
		permDefRepo:  permDefRepo,
		eventBus:     eventBus,
		txManager:    txManager,
	}
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

	memberRole, err := s.roleRepo.FindByName(ctx, appID, tenantID, defaultRoleName)
	if err != nil {
		if !errors.Is(err, domain.ErrRoleNotFound) {
			return err
		}
		slog.Warn("default member role not found, skipping auto-assign", "user_id", userID.String(), "error", err)
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

	templates, err := s.resolveTemplates(ctx, tenantID)
	if err != nil {
		return err
	}
	slog.Info("resolved template roles for new application",
		"app_id", appID.String(), "count", len(templates))

	return s.txManager.Execute(ctx, func(txCtx context.Context) error {
		creatorRole, err := s.seedRolesFromTemplates(txCtx, appID, tenantID, templates)
		if err != nil {
			return err
		}

		if !createdBy.IsEmpty() && creatorRole != nil {
			uar := &domain.UserAppRole{
				UserID:     createdBy,
				AppID:      appID,
				RoleID:     creatorRole.ID,
				TenantID:   tenantID,
				AssignedAt: time.Now(),
			}
			if err := s.roleRepo.SaveUserAppRole(txCtx, uar); err != nil {
				return err
			}
			slog.Info("assigned creator role to app creator",
				"user_id", createdBy.String(), "app_id", appID.String(), "role", creatorRole.Name)
		}

		if err := s.syncBuiltinPermissions(txCtx, appID); err != nil {
			return err
		}

		slog.Info("seeded roles and synced builtin permissions", "app_id", appID.String())
		return nil
	})
}

// resolveTemplates returns template roles for the tenant.
// Falls back to builtin defaults when no DB templates exist.
func (s *Subscriber) resolveTemplates(ctx context.Context, tenantID shared.TenantID) ([]*domain.Role, error) {
	templates, err := s.templateProv.FindTemplates(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if len(templates) > 0 {
		return templates, nil
	}
	return domain.BuiltinTemplateRoles(), nil
}

// seedRolesFromTemplates clones template roles into the new app.
// Returns the role marked as IsDefaultForCreator (if any).
func (s *Subscriber) seedRolesFromTemplates(ctx context.Context, appID shared.AppID, tenantID shared.TenantID, templates []*domain.Role) (*domain.Role, error) {
	var creatorRole *domain.Role

	for _, tmpl := range templates {
		existing, err := s.roleRepo.FindByName(ctx, appID, tenantID, tmpl.Name)
		if err == nil && existing != nil {
			if tmpl.IsDefaultForCreator {
				creatorRole = existing
			}
			slog.Info("role already exists, skipping", "role", tmpl.Name, "app_id", appID.String())
			continue
		}
		if err != nil && !errors.Is(err, domain.ErrRoleNotFound) {
			return nil, err
		}

		role := tmpl.CloneForApp(appID, tenantID)
		if err := s.roleRepo.Save(ctx, role); err != nil {
			slog.Error("failed to seed role from template", "role", tmpl.Name, "error", err)
			return nil, err
		}

		if tmpl.IsDefaultForCreator {
			creatorRole = role
		}
	}

	return creatorRole, nil
}

func (s *Subscriber) syncBuiltinPermissions(ctx context.Context, appID shared.AppID) error {
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
			return err
		}
	}
	return nil
}
