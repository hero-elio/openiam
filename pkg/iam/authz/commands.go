package authz

import (
	"openiam/internal/authz/application/command"
	"openiam/internal/authz/application/query"
)

// Command / query DTOs accepted by Service.
type (
	CreateRoleCommand               = command.CreateRole
	AssignRoleCommand               = command.AssignRole
	GrantPermissionCommand          = command.GrantPermission
	RevokePermissionCommand         = command.RevokePermission
	GrantResourcePermissionCommand  = command.GrantResourcePermission
	RevokeResourcePermissionCommand = command.RevokeResourcePermission
	RegisterPermissionCommand       = command.RegisterPermission
	DeletePermissionCommand         = command.DeletePermission

	CheckPermissionQuery         = query.CheckPermission
	CheckResourcePermissionQuery = query.CheckResourcePermission
	ListRolesQuery               = query.ListRoles
	ListUserRolesQuery           = query.ListUserRoles
	ListRoleMembersQuery         = query.ListRoleMembers
	ListResourcePermissionsQuery = query.ListResourcePermissions
	ListPermissionDefinitionsQuery = query.ListPermissionDefinitions
)
