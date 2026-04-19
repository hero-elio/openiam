package domain

import (
	"time"

	shared "openiam/internal/shared/domain"
)

type Role struct {
	shared.AggregateRoot
	ID                  shared.RoleID
	AppID               shared.AppID
	TenantID            shared.TenantID
	Name                string
	Description         string
	Permissions         []Permission
	IsSystem            bool
	IsTemplate          bool
	IsDefaultForCreator bool
	CreatedAt           time.Time
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

func NewSystemRole(appID shared.AppID, tenantID shared.TenantID, name, description string) *Role {
	now := time.Now()
	return &Role{
		ID:          shared.NewRoleID(),
		AppID:       appID,
		TenantID:    tenantID,
		Name:        name,
		Description: description,
		IsSystem:    true,
		CreatedAt:   now,
	}
}

func (r *Role) GrantPermission(p Permission) error {
	if r.HasPermission(p) {
		return ErrPermissionAlreadyGranted
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
			r.RecordEvent(PermissionRevokedEvent{
				RoleID:    r.ID,
				Resource:  p.Resource,
				Action:    p.Action,
				Timestamp: time.Now(),
			})
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

// CloneForApp creates a runtime copy of a template role bound to a real app.
func (r *Role) CloneForApp(appID shared.AppID, tenantID shared.TenantID) *Role {
	perms := make([]Permission, len(r.Permissions))
	copy(perms, r.Permissions)
	return &Role{
		ID:                  shared.NewRoleID(),
		AppID:               appID,
		TenantID:            tenantID,
		Name:                r.Name,
		Description:         r.Description,
		Permissions:         perms,
		IsSystem:            r.IsSystem,
		IsDefaultForCreator: r.IsDefaultForCreator,
		CreatedAt:           time.Now(),
	}
}

// BuiltinTemplateRoles returns the hardcoded template roles used when no
// database templates exist. Matches the legacy systemRoleSeeds behavior.
func BuiltinTemplateRoles() []*Role {
	return []*Role{
		{
			Name:                "super_admin",
			Description:         "Super administrator with all permissions",
			Permissions:         []Permission{NewPermission("*", "*")},
			IsSystem:            true,
			IsTemplate:          true,
			IsDefaultForCreator: true,
		},
		{
			Name:        "admin",
			Description: "Administrator with user and role management permissions",
			Permissions: []Permission{
				NewPermission(ResourceUsers, ActionRead),
				NewPermission(ResourceUsers, ActionUpdate),
				NewPermission(ResourceRoles, ActionAll),
				NewPermission(ResourcePermissions, ActionCheck),
			},
			IsSystem:   true,
			IsTemplate: true,
		},
		{
			Name:        "member",
			Description: "Basic member role (auto-assigned on registration)",
			IsSystem:    true,
			IsTemplate:  true,
		},
	}
}
