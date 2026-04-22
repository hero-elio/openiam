package domain

import (
	"context"
	"errors"
	"testing"

	shared "openiam/internal/shared/domain"
)

type fakeRoleRepo struct {
	roles []*Role
	err   error
}

func (f *fakeRoleRepo) Save(context.Context, *Role) error { return nil }

func (f *fakeRoleRepo) FindByID(context.Context, shared.RoleID) (*Role, error) { return nil, nil }

func (f *fakeRoleRepo) FindByName(context.Context, shared.AppID, shared.TenantID, string) (*Role, error) {
	return nil, nil
}

func (f *fakeRoleRepo) FindByUserAndApp(context.Context, shared.UserID, shared.AppID) ([]*Role, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.roles, nil
}

func (f *fakeRoleRepo) ListByApp(context.Context, shared.AppID) ([]*Role, error) { return nil, nil }

func (f *fakeRoleRepo) Delete(context.Context, shared.RoleID) error { return nil }

func (f *fakeRoleRepo) SaveUserAppRole(context.Context, *UserAppRole) error { return nil }

func (f *fakeRoleRepo) DeleteUserAppRole(context.Context, shared.UserID, shared.AppID, shared.RoleID) (bool, error) {
	return true, nil
}

func (f *fakeRoleRepo) FindUserAppRoles(context.Context, shared.UserID, shared.AppID) ([]*UserAppRole, error) {
	return nil, nil
}

func (f *fakeRoleRepo) ListUserAppRolesByRole(context.Context, shared.RoleID) ([]*UserAppRole, error) {
	return nil, nil
}

type fakeResourcePermRepo struct {
	allowed bool
	err     error
}

func (f *fakeResourcePermRepo) Save(context.Context, *ResourcePermission) error { return nil }

func (f *fakeResourcePermRepo) Delete(context.Context, shared.UserID, shared.AppID, string, string, string) error {
	return nil
}

func (f *fakeResourcePermRepo) FindByUserAndResource(context.Context, shared.UserID, shared.AppID, string, string) ([]*ResourcePermission, error) {
	return nil, nil
}

func (f *fakeResourcePermRepo) HasPermission(context.Context, shared.UserID, shared.AppID, string, string, string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.allowed, nil
}

func (f *fakeResourcePermRepo) ListByUser(context.Context, shared.UserID, shared.AppID) ([]*ResourcePermission, error) {
	return nil, nil
}

func TestEnforcer_IsAllowed(t *testing.T) {
	userID := shared.NewUserID()
	appID := shared.NewAppID()

	t.Run("allow via wildcard permission", func(t *testing.T) {
		role := &Role{
			Permissions: []Permission{
				NewPermission(ResourceRoles, ActionAll),
			},
		}
		e := NewEnforcer(&fakeRoleRepo{roles: []*Role{role}}, &fakeResourcePermRepo{})

		allowed, err := e.IsAllowed(context.Background(), userID, appID, ResourceRoles, ActionDelete)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatal("expected allowed via wildcard action")
		}
	})

	t.Run("deny when no role permission matches", func(t *testing.T) {
		role := &Role{
			Permissions: []Permission{
				NewPermission(ResourceUsers, ActionRead),
			},
		}
		e := NewEnforcer(&fakeRoleRepo{roles: []*Role{role}}, &fakeResourcePermRepo{})

		allowed, err := e.IsAllowed(context.Background(), userID, appID, ResourceRoles, ActionRead)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Fatal("expected denied when permission does not match")
		}
	})

	t.Run("propagates role repository error", func(t *testing.T) {
		repoErr := errors.New("role repo failed")
		e := NewEnforcer(&fakeRoleRepo{err: repoErr}, &fakeResourcePermRepo{})

		_, err := e.IsAllowed(context.Background(), userID, appID, ResourceUsers, ActionRead)
		if !errors.Is(err, repoErr) {
			t.Fatalf("expected repo error passthrough, got %v", err)
		}
	})
}

func TestEnforcer_IsResourceAllowed(t *testing.T) {
	userID := shared.NewUserID()
	appID := shared.NewAppID()

	t.Run("short-circuit allow from role permission", func(t *testing.T) {
		role := &Role{
			Permissions: []Permission{
				NewPermission("document", ActionRead),
			},
		}
		resRepo := &fakeResourcePermRepo{allowed: false}
		e := NewEnforcer(&fakeRoleRepo{roles: []*Role{role}}, resRepo)

		allowed, err := e.IsResourceAllowed(context.Background(), userID, appID, "document", "doc-1", ActionRead)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatal("expected allowed by role permission")
		}
	})

	t.Run("fallback to resource permission repository", func(t *testing.T) {
		e := NewEnforcer(&fakeRoleRepo{roles: nil}, &fakeResourcePermRepo{allowed: true})

		allowed, err := e.IsResourceAllowed(context.Background(), userID, appID, "document", "doc-1", ActionRead)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Fatal("expected allowed by resource-level permission")
		}
	})

	t.Run("propagates resource repository error", func(t *testing.T) {
		repoErr := errors.New("resource repo failed")
		e := NewEnforcer(&fakeRoleRepo{roles: nil}, &fakeResourcePermRepo{err: repoErr})

		_, err := e.IsResourceAllowed(context.Background(), userID, appID, "document", "doc-1", ActionRead)
		if !errors.Is(err, repoErr) {
			t.Fatalf("expected repo error passthrough, got %v", err)
		}
	})

	t.Run("propagates role repository error before resource fallback", func(t *testing.T) {
		roleErr := errors.New("role repo failed")
		e := NewEnforcer(&fakeRoleRepo{err: roleErr}, &fakeResourcePermRepo{allowed: true})

		_, err := e.IsResourceAllowed(context.Background(), userID, appID, "document", "doc-1", ActionRead)
		if !errors.Is(err, roleErr) {
			t.Fatalf("expected role repo error passthrough, got %v", err)
		}
	})
}
