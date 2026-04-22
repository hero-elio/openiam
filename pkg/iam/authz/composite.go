package authz

import (
	"context"
)

// ComposeSubjectExistence merges N partials into a single
// SubjectExistence implementation. UserExists / AppExists short-circuit
// on the first partial that returns either an affirmative answer or a
// real error; "not found" answers from earlier partials fall through
// to the next.
//
// The typical wiring is two partials — identity provides UserExists,
// tenant provides AppExists — but the contract works for any N so
// future modules (e.g. service-account directory) can join the chain
// without touching this file.
func ComposeSubjectExistence(parts ...SubjectExistencePartial) SubjectExistence {
	return composedExistence{parts: parts}
}

type composedExistence struct {
	parts []SubjectExistencePartial
}

func (c composedExistence) UserExists(ctx context.Context, id UserID) (bool, error) {
	for _, p := range c.parts {
		ok, err := p.UserExists(ctx, id)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

func (c composedExistence) AppExists(ctx context.Context, id AppID) (bool, error) {
	for _, p := range c.parts {
		ok, err := p.AppExists(ctx, id)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// NoOpSubjectExistence is the explicit "skip the pre-check" stand-in
// for deployments that don't want to wire identity / tenant. Every
// query reports the subject as existing so the authz service writes
// the grant without complaint.
//
// Pass it explicitly in Deps.SubjectExistence rather than leaving the
// field nil; readers of the deployment config then know the choice was
// intentional.
type NoOpSubjectExistence struct{}

func (NoOpSubjectExistence) UserExists(context.Context, UserID) (bool, error) { return true, nil }
func (NoOpSubjectExistence) AppExists(context.Context, AppID) (bool, error)   { return true, nil }

var _ SubjectExistence = NoOpSubjectExistence{}
var _ SubjectExistence = composedExistence{}
