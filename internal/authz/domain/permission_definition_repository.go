package domain

import (
	"context"

	shared "openiam/internal/shared/domain"
)

type PermissionDefinitionRepository interface {
	Upsert(ctx context.Context, pd *PermissionDefinition) error
	Delete(ctx context.Context, appID shared.AppID, resource, action string) error
	ListByApp(ctx context.Context, appID shared.AppID) ([]*PermissionDefinition, error)
	FindByKey(ctx context.Context, appID shared.AppID, resource, action string) (*PermissionDefinition, error)
}
