package domain

import (
	"context"

	shared "openiam/internal/shared/domain"
)

type RoleRepository interface {
	Save(ctx context.Context, role *Role) error
	FindByID(ctx context.Context, id shared.RoleID) (*Role, error)
	FindByName(ctx context.Context, appID shared.AppID, tenantID shared.TenantID, name string) (*Role, error)
	FindByUserAndApp(ctx context.Context, userID shared.UserID, appID shared.AppID) ([]*Role, error)
	ListByApp(ctx context.Context, appID shared.AppID) ([]*Role, error)
	Delete(ctx context.Context, id shared.RoleID) error

	SaveUserAppRole(ctx context.Context, uar *UserAppRole) error
	// DeleteUserAppRole removes the assignment if it exists. The bool reports
	// whether a row was actually deleted, so callers can keep the operation
	// idempotent (e.g. avoid emitting an Unassigned event for a no-op).
	DeleteUserAppRole(ctx context.Context, userID shared.UserID, appID shared.AppID, roleID shared.RoleID) (bool, error)
	FindUserAppRoles(ctx context.Context, userID shared.UserID, appID shared.AppID) ([]*UserAppRole, error)
	// ListUserAppRolesByRole returns every (user, app, role, tenant)
	// assignment row that points at roleID. Used by admin tooling to
	// answer "who has this role?" without joining identity.
	ListUserAppRolesByRole(ctx context.Context, roleID shared.RoleID) ([]*UserAppRole, error)
}

// RoleTemplateProvider resolves template roles used to seed a new application.
// Kept separate from RoleRepository so consumers only depend on what they need.
type RoleTemplateProvider interface {
	FindTemplates(ctx context.Context, tenantID shared.TenantID) ([]*Role, error)
}
