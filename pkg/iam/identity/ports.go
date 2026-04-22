package identity

import (
	"openiam/internal/identity/domain"
)

// UserStore is the outbound persistence port the identity module uses
// to read and write user aggregates. The Postgres implementation lives
// in internal/identity/adapter/outbound/persistence and is exposed as
// part of pkg/iam/adapters/postgres.
type UserStore = domain.UserRepository
