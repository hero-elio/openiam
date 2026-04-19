package domain

const (
	ResourceTenants      = "tenants"
	ResourceApplications = "applications"
	ResourceUsers        = "users"
	ResourceRoles        = "roles"
	ResourcePermissions  = "permissions"
	ResourceResources    = "resources"
)

const (
	ActionCreate = "create"
	ActionRead   = "read"
	ActionUpdate = "update"
	ActionDelete = "delete"
	ActionAssign = "assign"
	ActionGrant  = "grant"
	ActionRevoke = "revoke"
	ActionCheck  = "check"
	ActionAll    = "*"
)

type BuiltinPermissionDef struct {
	Resource    string
	Action      string
	Description string
}

var BuiltinPermissions = []BuiltinPermissionDef{
	{ResourceTenants, ActionCreate, "Create tenants"},
	{ResourceTenants, ActionRead, "View tenants"},
	{ResourceTenants, ActionUpdate, "Update tenants"},
	{ResourceTenants, ActionDelete, "Delete tenants"},
	{ResourceApplications, ActionCreate, "Create applications"},
	{ResourceApplications, ActionRead, "View applications"},
	{ResourceApplications, ActionUpdate, "Update applications"},
	{ResourceApplications, ActionDelete, "Delete applications"},
	{ResourceRoles, ActionCreate, "Create roles"},
	{ResourceRoles, ActionRead, "View roles"},
	{ResourceRoles, ActionUpdate, "Update roles and their permissions"},
	{ResourceRoles, ActionDelete, "Delete roles"},
	{ResourceRoles, ActionAssign, "Assign/unassign roles to users"},
	{ResourceUsers, ActionRead, "View user list and profiles"},
	{ResourceUsers, ActionUpdate, "Update user profiles"},
	{ResourceUsers, ActionDelete, "Delete users"},
	{ResourcePermissions, ActionGrant, "Grant permissions"},
	{ResourcePermissions, ActionRevoke, "Revoke permissions"},
	{ResourcePermissions, ActionCheck, "Check permissions via API"},
	{ResourcePermissions, ActionRead, "View permission definitions"},
	{ResourcePermissions, ActionCreate, "Register permission definitions"},
	{ResourcePermissions, ActionDelete, "Delete permission definitions"},
	{ResourceResources, ActionGrant, "Grant resource-level permissions"},
	{ResourceResources, ActionRevoke, "Revoke resource-level permissions"},
	{ResourceResources, ActionRead, "View resource-level permissions"},
}
