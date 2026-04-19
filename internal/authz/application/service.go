package application

import (
	"context"
	"time"

	shared "openiam/internal/shared/domain"

	"openiam/internal/authz/application/command"
	"openiam/internal/authz/application/query"
	"openiam/internal/authz/domain"
)

type RoleDTO struct {
	ID          string
	AppID       string
	TenantID    string
	Name        string
	Description string
	Permissions []string
	IsSystem    bool
	CreatedAt   string
}

type UserAppRoleDTO struct {
	UserID     string
	AppID      string
	RoleID     string
	TenantID   string
	AssignedAt string
}

type CheckPermissionResult struct {
	Allowed bool
}

type ResourcePermissionDTO struct {
	ID           string
	UserID       string
	AppID        string
	TenantID     string
	ResourceType string
	ResourceID   string
	Action       string
	GrantedAt    string
	GrantedBy    string
}

type PermissionDefinitionDTO struct {
	ID          string
	AppID       string
	Resource    string
	Action      string
	Description string
	IsBuiltin   bool
	CreatedAt   string
}

type AuthzAppService struct {
	roleRepo    domain.RoleRepository
	resPermRepo domain.ResourcePermissionRepository
	permDefRepo domain.PermissionDefinitionRepository
	enforcer    *domain.Enforcer
	eventBus    shared.EventBus
	txManager   shared.TxManager
}

func NewAuthzAppService(
	roleRepo domain.RoleRepository,
	resPermRepo domain.ResourcePermissionRepository,
	permDefRepo domain.PermissionDefinitionRepository,
	enforcer *domain.Enforcer,
	eventBus shared.EventBus,
	txManager shared.TxManager,
) *AuthzAppService {
	return &AuthzAppService{
		roleRepo:    roleRepo,
		resPermRepo: resPermRepo,
		permDefRepo: permDefRepo,
		enforcer:    enforcer,
		eventBus:    eventBus,
		txManager:   txManager,
	}
}

func (s *AuthzAppService) CreateRole(ctx context.Context, cmd *command.CreateRole) (shared.RoleID, error) {
	appID := shared.AppID(cmd.AppID)
	tenantID := shared.TenantID(cmd.TenantID)

	role := domain.NewRole(appID, tenantID, cmd.Name, cmd.Description)

	if err := s.txManager.Execute(ctx, func(txCtx context.Context) error {
		existing, err := s.roleRepo.FindByName(txCtx, appID, cmd.Name)
		if err != nil && err != domain.ErrRoleNotFound {
			return err
		}
		if existing != nil {
			return domain.ErrRoleAlreadyExists
		}
		if err := s.roleRepo.Save(txCtx, role); err != nil {
			return err
		}
		return s.eventBus.Publish(txCtx, role.PullEvents()...)
	}); err != nil {
		return "", err
	}

	return role.ID, nil
}

func (s *AuthzAppService) DeleteRole(ctx context.Context, roleID string) error {
	id := shared.RoleID(roleID)
	role, err := s.roleRepo.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if role.IsSystem {
		return domain.ErrSystemRoleProtected
	}
	return s.txManager.Execute(ctx, func(txCtx context.Context) error {
		return s.roleRepo.Delete(txCtx, id)
	})
}

func (s *AuthzAppService) AssignRole(ctx context.Context, cmd *command.AssignRole) error {
	userID := shared.UserID(cmd.UserID)
	appID := shared.AppID(cmd.AppID)
	roleID := shared.RoleID(cmd.RoleID)
	tenantID := shared.TenantID(cmd.TenantID)

	if _, err := s.roleRepo.FindByID(ctx, roleID); err != nil {
		return err
	}

	uar := &domain.UserAppRole{
		UserID:     userID,
		AppID:      appID,
		RoleID:     roleID,
		TenantID:   tenantID,
		AssignedAt: time.Now(),
	}

	return s.txManager.Execute(ctx, func(txCtx context.Context) error {
		if err := s.roleRepo.SaveUserAppRole(txCtx, uar); err != nil {
			return err
		}
		return s.eventBus.Publish(txCtx, domain.RoleAssignedEvent{
			UserID:    userID,
			AppID:     appID,
			RoleID:    roleID,
			TenantID:  tenantID,
			Timestamp: uar.AssignedAt,
		})
	})
}

func (s *AuthzAppService) GrantPermission(ctx context.Context, cmd *command.GrantPermission) error {
	roleID := shared.RoleID(cmd.RoleID)

	role, err := s.roleRepo.FindByID(ctx, roleID)
	if err != nil {
		return err
	}

	perm := domain.NewPermission(cmd.Resource, cmd.Action)
	if err = role.GrantPermission(perm); err != nil {
		return err
	}

	return s.txManager.Execute(ctx, func(txCtx context.Context) error {
		if err = s.roleRepo.Save(txCtx, role); err != nil {
			return err
		}
		return s.eventBus.Publish(txCtx, role.PullEvents()...)
	})
}

func (s *AuthzAppService) RevokePermission(ctx context.Context, cmd *command.RevokePermission) error {
	roleID := shared.RoleID(cmd.RoleID)

	role, err := s.roleRepo.FindByID(ctx, roleID)
	if err != nil {
		return err
	}

	perm := domain.NewPermission(cmd.Resource, cmd.Action)
	if err := role.RevokePermission(perm); err != nil {
		return err
	}

	return s.txManager.Execute(ctx, func(txCtx context.Context) error {
		if err := s.roleRepo.Save(txCtx, role); err != nil {
			return err
		}
		return s.eventBus.Publish(txCtx, role.PullEvents()...)
	})
}

func (s *AuthzAppService) UnassignRole(ctx context.Context, userID, appID, roleID string) error {
	uid := shared.UserID(userID)
	aid := shared.AppID(appID)
	rid := shared.RoleID(roleID)

	return s.txManager.Execute(ctx, func(txCtx context.Context) error {
		if err := s.roleRepo.DeleteUserAppRole(txCtx, uid, aid, rid); err != nil {
			return err
		}
		return s.eventBus.Publish(txCtx, domain.RoleUnassignedEvent{
			UserID:    uid,
			AppID:     aid,
			RoleID:    rid,
			Timestamp: time.Now(),
		})
	})
}

func (s *AuthzAppService) CheckPermission(ctx context.Context, q *query.CheckPermission) (*CheckPermissionResult, error) {
	allowed, err := s.enforcer.IsAllowed(
		ctx,
		shared.UserID(q.UserID),
		shared.AppID(q.AppID),
		q.Resource,
		q.Action,
	)
	if err != nil {
		return nil, err
	}
	return &CheckPermissionResult{Allowed: allowed}, nil
}

func (s *AuthzAppService) ListRoles(ctx context.Context, q *query.ListRoles) ([]*RoleDTO, error) {
	roles, err := s.roleRepo.ListByApp(ctx, shared.AppID(q.AppID))
	if err != nil {
		return nil, err
	}

	dtos := make([]*RoleDTO, 0, len(roles))
	for _, r := range roles {
		dtos = append(dtos, toRoleDTO(r))
	}
	return dtos, nil
}

func (s *AuthzAppService) ListUserRoles(ctx context.Context, q *query.ListUserRoles) ([]*UserAppRoleDTO, error) {
	uars, err := s.roleRepo.FindUserAppRoles(ctx, shared.UserID(q.UserID), shared.AppID(q.AppID))
	if err != nil {
		return nil, err
	}

	dtos := make([]*UserAppRoleDTO, 0, len(uars))
	for _, uar := range uars {
		dtos = append(dtos, &UserAppRoleDTO{
			UserID:     uar.UserID.String(),
			AppID:      uar.AppID.String(),
			RoleID:     uar.RoleID.String(),
			TenantID:   uar.TenantID.String(),
			AssignedAt: uar.AssignedAt.Format(time.RFC3339),
		})
	}
	return dtos, nil
}

// --- Resource Permission (ACL) methods ---

func (s *AuthzAppService) GrantResourcePermission(ctx context.Context, cmd *command.GrantResourcePermission) error {
	now := time.Now()
	rp := &domain.ResourcePermission{
		UserID:       shared.UserID(cmd.UserID),
		AppID:        shared.AppID(cmd.AppID),
		TenantID:     shared.TenantID(cmd.TenantID),
		ResourceType: cmd.ResourceType,
		ResourceID:   cmd.ResourceID,
		Action:       cmd.Action,
		GrantedAt:    now,
		GrantedBy:    shared.UserID(cmd.GrantedBy),
	}

	return s.txManager.Execute(ctx, func(txCtx context.Context) error {
		if err := s.resPermRepo.Save(txCtx, rp); err != nil {
			return err
		}
		return s.eventBus.Publish(txCtx, domain.ResourcePermissionGrantedEvent{
			UserID:       rp.UserID,
			AppID:        rp.AppID,
			ResourceType: rp.ResourceType,
			ResourceID:   rp.ResourceID,
			Action:       rp.Action,
			GrantedBy:    rp.GrantedBy,
			Timestamp:    now,
		})
	})
}

func (s *AuthzAppService) RevokeResourcePermission(ctx context.Context, cmd *command.RevokeResourcePermission) error {
	userID := shared.UserID(cmd.UserID)
	appID := shared.AppID(cmd.AppID)

	return s.txManager.Execute(ctx, func(txCtx context.Context) error {
		if err := s.resPermRepo.Delete(txCtx, userID, appID, cmd.ResourceType, cmd.ResourceID, cmd.Action); err != nil {
			return err
		}
		return s.eventBus.Publish(txCtx, domain.ResourcePermissionRevokedEvent{
			UserID:       userID,
			AppID:        appID,
			ResourceType: cmd.ResourceType,
			ResourceID:   cmd.ResourceID,
			Action:       cmd.Action,
			Timestamp:    time.Now(),
		})
	})
}

func (s *AuthzAppService) CheckResourcePermission(ctx context.Context, q *query.CheckResourcePermission) (*CheckPermissionResult, error) {
	allowed, err := s.enforcer.IsResourceAllowed(
		ctx,
		shared.UserID(q.UserID),
		shared.AppID(q.AppID),
		q.ResourceType,
		q.ResourceID,
		q.Action,
	)
	if err != nil {
		return nil, err
	}
	return &CheckPermissionResult{Allowed: allowed}, nil
}

func (s *AuthzAppService) ListResourcePermissions(ctx context.Context, q *query.ListResourcePermissions) ([]*ResourcePermissionDTO, error) {
	perms, err := s.resPermRepo.ListByUser(ctx, shared.UserID(q.UserID), shared.AppID(q.AppID))
	if err != nil {
		return nil, err
	}

	dtos := make([]*ResourcePermissionDTO, 0, len(perms))
	for _, p := range perms {
		dtos = append(dtos, &ResourcePermissionDTO{
			ID:           p.ID,
			UserID:       p.UserID.String(),
			AppID:        p.AppID.String(),
			TenantID:     p.TenantID.String(),
			ResourceType: p.ResourceType,
			ResourceID:   p.ResourceID,
			Action:       p.Action,
			GrantedAt:    p.GrantedAt.Format(time.RFC3339),
			GrantedBy:    p.GrantedBy.String(),
		})
	}
	return dtos, nil
}

// --- Permission Definition (registry) methods ---

func (s *AuthzAppService) RegisterPermission(ctx context.Context, cmd *command.RegisterPermission) error {
	pd := &domain.PermissionDefinition{
		AppID:       shared.AppID(cmd.AppID),
		Resource:    cmd.Resource,
		Action:      cmd.Action,
		Description: cmd.Description,
		IsBuiltin:   false,
		CreatedAt:   time.Now(),
	}
	return s.permDefRepo.Upsert(ctx, pd)
}

func (s *AuthzAppService) DeletePermissionDefinition(ctx context.Context, cmd *command.DeletePermission) error {
	return s.permDefRepo.Delete(ctx, shared.AppID(cmd.AppID), cmd.Resource, cmd.Action)
}

func (s *AuthzAppService) ListPermissionDefinitions(ctx context.Context, q *query.ListPermissionDefinitions) ([]*PermissionDefinitionDTO, error) {
	defs, err := s.permDefRepo.ListByApp(ctx, shared.AppID(q.AppID))
	if err != nil {
		return nil, err
	}

	dtos := make([]*PermissionDefinitionDTO, 0, len(defs))
	for _, d := range defs {
		dtos = append(dtos, &PermissionDefinitionDTO{
			ID:          d.ID,
			AppID:       d.AppID.String(),
			Resource:    d.Resource,
			Action:      d.Action,
			Description: d.Description,
			IsBuiltin:   d.IsBuiltin,
			CreatedAt:   d.CreatedAt.Format(time.RFC3339),
		})
	}
	return dtos, nil
}

func (s *AuthzAppService) SyncBuiltinPermissions(ctx context.Context, appID shared.AppID) error {
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

func toRoleDTO(r *domain.Role) *RoleDTO {
	perms := make([]string, 0, len(r.Permissions))
	for _, p := range r.Permissions {
		perms = append(perms, p.String())
	}
	return &RoleDTO{
		ID:          r.ID.String(),
		AppID:       r.AppID.String(),
		TenantID:    r.TenantID.String(),
		Name:        r.Name,
		Description: r.Description,
		Permissions: perms,
		IsSystem:    r.IsSystem,
		CreatedAt:   r.CreatedAt.Format(time.RFC3339),
	}
}
