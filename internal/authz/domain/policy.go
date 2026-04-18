package domain

import (
	"time"

	shared "openiam/internal/shared/domain"
)

type UserAppRole struct {
	UserID     shared.UserID
	AppID      shared.AppID
	RoleID     shared.RoleID
	TenantID   shared.TenantID
	AssignedAt time.Time
}
