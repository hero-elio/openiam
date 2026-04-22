// Package authz is the public SDK surface for the IAM authorization
// module: roles, role assignments, resource-level permissions, and the
// permission-check Checker that transports use to gate routes.
//
// Phase 2c lifts the public types and Builder API; canonical
// implementations stay under internal/authz until Phase 5.
package authz

import (
	"openiam/internal/authz/domain"
	shared "openiam/internal/shared/domain"
)

// Identifier aliases.
type (
	UserID   = shared.UserID
	TenantID = shared.TenantID
	AppID    = shared.AppID
	RoleID   = shared.RoleID
)

// Domain types re-exported for SDK consumers.
type (
	Role               = domain.Role
	UserAppRole        = domain.UserAppRole
	Permission         = domain.Permission
	ResourcePermission = domain.ResourcePermission
	PermissionDefinition = domain.PermissionDefinition
	BuiltinPermissionDef = domain.BuiltinPermissionDef

	RoleCreatedEvent               = domain.RoleCreatedEvent
	RoleAssignedEvent              = domain.RoleAssignedEvent
	RoleUnassignedEvent            = domain.RoleUnassignedEvent
	PermissionGrantedEvent         = domain.PermissionGrantedEvent
	PermissionRevokedEvent         = domain.PermissionRevokedEvent
	ResourcePermissionGrantedEvent = domain.ResourcePermissionGrantedEvent
	ResourcePermissionRevokedEvent = domain.ResourcePermissionRevokedEvent
)

// Domain event names re-exported for SDK subscribers.
const (
	EventRoleCreated               = domain.EventRoleCreated
	EventRoleAssigned              = domain.EventRoleAssigned
	EventRoleUnassigned            = domain.EventRoleUnassigned
	EventPermissionGranted         = domain.EventPermissionGranted
	EventPermissionRevoked         = domain.EventPermissionRevoked
	EventResourcePermissionGranted = domain.EventResourcePermissionGranted
	EventResourcePermissionRevoked = domain.EventResourcePermissionRevoked
)

// BuiltinPermissions is the canonical permission catalog the
// SyncBuiltinPermissions seed flow registers per app.
var BuiltinPermissions = domain.BuiltinPermissions

// Domain sentinel errors re-exported.
var (
	ErrRoleNotFound             = domain.ErrRoleNotFound
	ErrRoleAlreadyExists        = domain.ErrRoleAlreadyExists
	ErrRoleAppMismatch          = domain.ErrRoleAppMismatch
	ErrPermissionAlreadyGranted = domain.ErrPermissionAlreadyGranted
	ErrSystemRoleProtected      = domain.ErrSystemRoleProtected
	ErrUnknownSubject           = domain.ErrUnknownSubject
)
