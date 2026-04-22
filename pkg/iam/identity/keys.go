package identity

// Permission keys this module's transport adapters consult against the
// authz Checker.
//
// Each module owns its own permission strings instead of reaching into
// pkg/iam/authz/keys; that way pkg/iam/identity is independently
// importable — an SDK consumer that only wants identity doesn't have to
// drag in authz just to know what string identifies the "users:read"
// permission. The strings stay aligned with authz.BuiltinPermissions
// because authz seeds the same vocabulary on boot.
const (
	// ResourceUsers is the permission resource label for user records.
	ResourceUsers = "users"
)

const (
	ActionRead   = "read"
	ActionUpdate = "update"
	ActionDelete = "delete"
)
