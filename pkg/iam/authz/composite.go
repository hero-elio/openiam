package authz

import (
	"context"
)

// UserExistence is the user-side half of SubjectExistence — the slice
// the identity module owns. The bridge returned by
// pkg/iam/identity.SubjectExistenceFor satisfies it directly.
type UserExistence interface {
	UserExists(ctx context.Context, id UserID) (bool, error)
}

// AppExistence is the app-side half of SubjectExistence — the slice
// the tenant module owns. The bridge returned by
// pkg/iam/tenant.SubjectExistenceFor satisfies it directly.
type AppExistence interface {
	AppExists(ctx context.Context, id AppID) (bool, error)
}

// ComposeSubjectExistence merges a UserExistence and an AppExistence
// into the combined port the authz service consumes. Either argument
// may be nil; missing halves report "not found" so a misconfiguration
// fails closed (the authz service refuses the grant) rather than
// silently allowing it.
//
// The typical wiring is identity.SubjectExistenceFor for the user side
// and tenant.SubjectExistenceFor for the app side. Standalone
// deployments can skip composition entirely by passing
// NoOpSubjectExistence to Deps.SubjectExistence.
func ComposeSubjectExistence(users UserExistence, apps AppExistence) SubjectExistence {
	return composedExistence{users: users, apps: apps}
}

type composedExistence struct {
	users UserExistence
	apps  AppExistence
}

func (c composedExistence) UserExists(ctx context.Context, id UserID) (bool, error) {
	if c.users == nil {
		return false, nil
	}
	return c.users.UserExists(ctx, id)
}

func (c composedExistence) AppExists(ctx context.Context, id AppID) (bool, error) {
	if c.apps == nil {
		return false, nil
	}
	return c.apps.AppExists(ctx, id)
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
