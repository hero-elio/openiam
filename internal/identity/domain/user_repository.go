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
	List(ctx context.Context, filter ListUsersFilter) ([]*User, error)
}

// ListUsersFilter narrows a user list query. TenantID is optional; an
// empty value selects across every tenant the caller can already see
// at the transport layer (typically the platform-admin scope).
// EmailLike performs a SQL LIKE-style suffix/prefix match when set;
// callers are expected to supply percent signs themselves.
type ListUsersFilter struct {
	TenantID  shared.TenantID
	EmailLike string
	Limit     int
	Offset    int
}
