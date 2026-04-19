package domain

import (
	"time"

	shared "openiam/internal/shared/domain"
)

type ResourcePermission struct {
	ID           string
	UserID       shared.UserID
	AppID        shared.AppID
	TenantID     shared.TenantID
	ResourceType string
	ResourceID   string
	Action       string
	GrantedAt    time.Time
	GrantedBy    shared.UserID
}
