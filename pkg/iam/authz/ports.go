package authz

import (
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
