package authz

import (
	"context"

	authzApp "openiam/internal/authz/application"
)

// Public DTOs returned by Service. The struct definitions live in
// internal/authz/application; the aliases here are what SDK consumers
// depend on.
type (
	RoleDTO                 = authzApp.RoleDTO
	UserAppRoleDTO          = authzApp.UserAppRoleDTO
	ResourcePermissionDTO   = authzApp.ResourcePermissionDTO
	PermissionDefinitionDTO = authzApp.PermissionDefinitionDTO
	CheckPermissionResult   = authzApp.CheckPermissionResult
)

// Service is the protocol-agnostic surface of the authz module.
type Service interface {
	// --- Role management ---
	CreateRole(ctx context.Context, cmd *CreateRoleCommand) (RoleID, error)
	DeleteRole(ctx context.Context, roleID string) error
	ListRoles(ctx context.Context, q *ListRolesQuery) ([]*RoleDTO, error)

	// --- Role assignment ---
	AssignRole(ctx context.Context, cmd *AssignRoleCommand) error
	UnassignRole(ctx context.Context, userID, appID, roleID string) error
	ListUserRoles(ctx context.Context, q *ListUserRolesQuery) ([]*UserAppRoleDTO, error)
	ListRoleMembers(ctx context.Context, q *ListRoleMembersQuery) ([]*UserAppRoleDTO, error)

	// --- Role permissions ---
	GrantPermission(ctx context.Context, cmd *GrantPermissionCommand) error
	RevokePermission(ctx context.Context, cmd *RevokePermissionCommand) error

	// --- Permission checks ---
	CheckPermission(ctx context.Context, q *CheckPermissionQuery) (*CheckPermissionResult, error)
	CheckResourcePermission(ctx context.Context, q *CheckResourcePermissionQuery) (*CheckPermissionResult, error)

	// --- Resource ACL ---
	GrantResourcePermission(ctx context.Context, cmd *GrantResourcePermissionCommand) error
	RevokeResourcePermission(ctx context.Context, cmd *RevokeResourcePermissionCommand) error
	ListResourcePermissions(ctx context.Context, q *ListResourcePermissionsQuery) ([]*ResourcePermissionDTO, error)

	// --- Permission definition registry ---
	RegisterPermission(ctx context.Context, cmd *RegisterPermissionCommand) error
	DeletePermissionDefinition(ctx context.Context, cmd *DeletePermissionCommand) error
	ListPermissionDefinitions(ctx context.Context, q *ListPermissionDefinitionsQuery) ([]*PermissionDefinitionDTO, error)

	// SyncBuiltinPermissions registers the BuiltinPermissions catalog
	// for a given app. Idempotent; safe to call on every boot.
	SyncBuiltinPermissions(ctx context.Context, appID AppID) error

	// SetSubjectExistence wires (or rewires) the cross-module port
	// the service consults before recording grants. Safe to call
	// multiple times — the last setter wins.
	SetSubjectExistence(se SubjectExistence)
}
