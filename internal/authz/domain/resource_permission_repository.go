package domain

import (
	"context"

	shared "openiam/internal/shared/domain"
)

type ResourcePermissionRepository interface {
	Save(ctx context.Context, rp *ResourcePermission) error
	Delete(ctx context.Context, userID shared.UserID, appID shared.AppID,
		resourceType, resourceID, action string) error
	FindByUserAndResource(ctx context.Context, userID shared.UserID,
		appID shared.AppID, resourceType, resourceID string) ([]*ResourcePermission, error)
	HasPermission(ctx context.Context, userID shared.UserID,
		appID shared.AppID, resourceType, resourceID, action string) (bool, error)
	ListByUser(ctx context.Context, userID shared.UserID,
		appID shared.AppID) ([]*ResourcePermission, error)
}
