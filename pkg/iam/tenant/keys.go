package tenant

// Permission keys this module's transport adapters consult against the
// authz Checker. Owned here so pkg/iam/tenant is independently
// importable; the strings stay aligned with authz.BuiltinPermissions
// (authz seeds the same vocabulary on boot).
const (
	ResourceTenants      = "tenants"
	ResourceApplications = "applications"
)

const (
	ActionCreate = "create"
	ActionRead   = "read"
	ActionUpdate = "update"
	ActionDelete = "delete"
)
