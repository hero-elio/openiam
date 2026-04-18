package domain

import (
	"context"

	shared "openiam/internal/shared/domain"
)

type Enforcer struct {
	roleRepo RoleRepository
}

func NewEnforcer(roleRepo RoleRepository) *Enforcer {
	return &Enforcer{roleRepo: roleRepo}
}

func (e *Enforcer) IsAllowed(ctx context.Context, userID shared.UserID, appID shared.AppID, resource, action string) (bool, error) {
	roles, err := e.roleRepo.FindByUserAndApp(ctx, userID, appID)
	if err != nil {
		return false, err
	}

	for _, role := range roles {
		for _, perm := range role.Permissions {
			if perm.Matches(resource, action) {
				return true, nil
			}
		}
	}
	return false, nil
}
