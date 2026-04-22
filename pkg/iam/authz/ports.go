package authz

import (
	"context"

	"openiam/internal/authz/domain"
)

// Outbound persistence ports the authz module uses. Postgres
// implementations are bundled in pkg/iam/adapters/postgres.
type (
	RoleStore                 = domain.RoleRepository
	ResourcePermissionStore   = domain.ResourcePermissionRepository
	PermissionDefinitionStore = domain.PermissionDefinitionRepository
)

// SubjectExistence is the cross-module port the authz service uses to
// refuse grants and assignments targeting unknown users or apps.
//
// In a typical deployment the implementation is composed from the
// identity module (UserExists) and the tenant module (AppExists) via
// ComposeSubjectExistence; standalone deployments can inject
// NoOpSubjectExistence to acknowledge they're skipping the check.
type SubjectExistence = domain.SubjectExistence

// SubjectExistencePartial is one half of SubjectExistence. The
// identity module supplies the user side; the tenant module supplies
// the app side. ComposeSubjectExistence merges them.
//
// The interface is defined here (rather than as a single anonymous
// closure) so future modules can advertise additional partials and
// the host can compose them without touching this file.
type SubjectExistencePartial interface {
	UserExists(ctx context.Context, id UserID) (bool, error)
	AppExists(ctx context.Context, id AppID) (bool, error)
}
