package identity

import (
	"context"

	identityApp "openiam/internal/identity/application"
)

// UserDTO is the public projection of a user record. The struct
// definition lives in internal/identity/application; this alias is
// what SDK consumers depend on.
type UserDTO = identityApp.UserDTO

// Service is the protocol-agnostic surface of the identity module.
//
// All errors returned here are domain errors (ErrUserNotFound,
// ErrEmailAlreadyTaken, …). Transport adapters translate them to
// their own status convention.
type Service interface {
	// RegisterUser provisions a new local user with email + password.
	// Returns the new user id.
	RegisterUser(ctx context.Context, cmd *RegisterUserCommand) (UserID, error)

	// RegisterExternalUser provisions (or returns the existing) user
	// for an external credential subject — used by SIWE / WebAuthn
	// first-time sign-in flows.
	RegisterExternalUser(ctx context.Context, cmd *RegisterExternalUserCommand) (UserID, error)

	// GetUser reads a single user by id.
	GetUser(ctx context.Context, q *GetUserQuery) (*UserDTO, error)

	// UserExists is a cheap "is this id known?" check used by other
	// modules (e.g. authz pre-checks before assigning a role).
	UserExists(ctx context.Context, id UserID) (bool, error)

	// ChangePassword rotates a user's password after re-verifying the
	// current one.
	ChangePassword(ctx context.Context, cmd *ChangePasswordCommand) error

	// UpdateProfile mutates display name / avatar.
	UpdateProfile(ctx context.Context, cmd *UpdateProfileCommand) error

	// FindByEmail looks up a user by email scoped to a tenant.
	FindByEmail(ctx context.Context, tenantID TenantID, email string) (*UserDTO, error)
}
