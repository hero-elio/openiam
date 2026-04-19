package domain

const (
	ResourceUsers       = "users"
	ResourceRoles       = "roles"
	ResourcePermissions = "permissions"
	ResourceResources   = "resources"
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
	{ResourceRoles, ActionCreate, "Create roles"},
	{ResourceRoles, ActionRead, "View roles"},
	{ResourceRoles, ActionUpdate, "Update roles and their permissions"},
	{ResourceRoles, ActionDelete, "Delete roles"},
	{ResourceRoles, ActionAssign, "Assign/unassign roles to users"},
	{ResourceUsers, ActionRead, "View user list and profiles"},
	{ResourceUsers, ActionUpdate, "Update user profiles"},
	{ResourceUsers, ActionDelete, "Delete users"},
	{ResourcePermissions, ActionCheck, "Check permissions via API"},
}
