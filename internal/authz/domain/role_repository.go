package domain

import (
	"context"

	shared "openiam/internal/shared/domain"
)

type RoleRepository interface {
	Save(ctx context.Context, role *Role) error
	FindByID(ctx context.Context, id shared.RoleID) (*Role, error)
	FindByName(ctx context.Context, appID shared.AppID, name string) (*Role, error)
	FindByUserAndApp(ctx context.Context, userID shared.UserID, appID shared.AppID) ([]*Role, error)
	ListByApp(ctx context.Context, appID shared.AppID) ([]*Role, error)
	Delete(ctx context.Context, id shared.RoleID) error

	SaveUserAppRole(ctx context.Context, uar *UserAppRole) error
	DeleteUserAppRole(ctx context.Context, userID shared.UserID, appID shared.AppID, roleID shared.RoleID) error
	FindUserAppRoles(ctx context.Context, userID shared.UserID, appID shared.AppID) ([]*UserAppRole, error)
}
