package domain

import (
	"time"

	shared "openiam/internal/shared/domain"
)

type Role struct {
	shared.AggregateRoot
	ID          shared.RoleID
	AppID       shared.AppID
	TenantID    shared.TenantID
	Name        string
	Description string
	Permissions []Permission
	IsSystem    bool
	CreatedAt   time.Time
}

func NewRole(appID shared.AppID, tenantID shared.TenantID, name, description string) *Role {
	now := time.Now()
	r := &Role{
		ID:          shared.NewRoleID(),
		AppID:       appID,
		TenantID:    tenantID,
		Name:        name,
		Description: description,
		CreatedAt:   now,
	}
	r.RecordEvent(RoleCreatedEvent{
		RoleID:    r.ID,
		AppID:     appID,
		TenantID:  tenantID,
		Name:      name,
		Timestamp: now,
	})
	return r
}

func (r *Role) GrantPermission(p Permission) error {
	if r.HasPermission(p) {
		return shared.ErrPermissionAlreadyGranted
	}
	r.Permissions = append(r.Permissions, p)
	r.RecordEvent(PermissionGrantedEvent{
		RoleID:    r.ID,
		Resource:  p.Resource,
		Action:    p.Action,
		Timestamp: time.Now(),
	})
	return nil
}

func (r *Role) RevokePermission(p Permission) error {
	for i, existing := range r.Permissions {
		if existing.Resource == p.Resource && existing.Action == p.Action {
			r.Permissions = append(r.Permissions[:i], r.Permissions[i+1:]...)
			return nil
		}
	}
	return shared.ErrNotFound
}

func (r *Role) HasPermission(p Permission) bool {
	for _, existing := range r.Permissions {
		if existing.Resource == p.Resource && existing.Action == p.Action {
			return true
		}
	}
	return false
}
