package domain

import (
	"time"

	shared "openiam/internal/shared/domain"
)

type PermissionDefinition struct {
	ID          string
	AppID       shared.AppID
	Resource    string
	Action      string
	Description string
	IsBuiltin   bool
	CreatedAt   time.Time
}
