package domain

import (
	"context"

	shared "openiam/internal/shared/domain"
)

type Enforcer struct {
	roleRepo    RoleRepository
	resPermRepo ResourcePermissionRepository
}

func NewEnforcer(roleRepo RoleRepository, resPermRepo ResourcePermissionRepository) *Enforcer {
	return &Enforcer{roleRepo: roleRepo, resPermRepo: resPermRepo}
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

func (e *Enforcer) IsResourceAllowed(ctx context.Context, userID shared.UserID, appID shared.AppID, resourceType, resourceID, action string) (bool, error) {
	allowed, err := e.IsAllowed(ctx, userID, appID, resourceType, action)
	if err != nil {
		return false, err
	}
	if allowed {
		return true, nil
	}

	return e.resPermRepo.HasPermission(ctx, userID, appID, resourceType, resourceID, action)
}
