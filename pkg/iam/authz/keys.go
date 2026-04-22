package authz

import authzDomain "openiam/internal/authz/domain"

// Permission keys this module's transport adapters consult against the
// Checker. Aliased through to internal/authz/domain so the in-tree
// callers keep working until Phase 5 inverts the dependency direction.
const (
	ResourceRoles       = authzDomain.ResourceRoles
	ResourcePermissions = authzDomain.ResourcePermissions
	ResourceResources   = authzDomain.ResourceResources
)

const (
	ActionCreate = authzDomain.ActionCreate
	ActionRead   = authzDomain.ActionRead
	ActionUpdate = authzDomain.ActionUpdate
	ActionDelete = authzDomain.ActionDelete
	ActionAssign = authzDomain.ActionAssign
	ActionGrant  = authzDomain.ActionGrant
	ActionRevoke = authzDomain.ActionRevoke
	ActionCheck  = authzDomain.ActionCheck
	ActionAll    = authzDomain.ActionAll
)
