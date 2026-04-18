package domain

import (
	"context"

	shared "openiam/internal/shared/domain"
)

type UserRepository interface {
	Save(ctx context.Context, user *User) error
	FindByID(ctx context.Context, id shared.UserID) (*User, error)
	FindByEmail(ctx context.Context, tenantID shared.TenantID, email Email) (*User, error)
	ExistsByEmail(ctx context.Context, tenantID shared.TenantID, email Email) (bool, error)
}
