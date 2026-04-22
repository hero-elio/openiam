package domain

import (
	"context"

	shared "openiam/internal/shared/domain"
)

// SubjectExistence is the outbound port the authz context uses to
// refuse grants targeting unknown users or applications. Splitting it
// per resource type would be more ISP-pure, but in practice every
// adapter is wired by the same engine call and every grant flow needs
// at least one of the methods, so a single interface keeps wiring
// trivial without forcing real-world callers to juggle two ports.
//
// Adapters live in the identity and tenant contexts and the engine
// composes them into a single value that implements this interface.
type SubjectExistence interface {
	UserExists(ctx context.Context, id shared.UserID) (bool, error)
	AppExists(ctx context.Context, id shared.AppID) (bool, error)
}
