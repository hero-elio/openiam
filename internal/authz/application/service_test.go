package application

import (
	"context"
	"testing"

	"openiam/internal/authz/application/command"
	"openiam/internal/authz/domain"
	shared "openiam/internal/shared/domain"
)

type fakeRoleRepo struct {
	role           *domain.Role
	findByIDErr    error
	userAssignments []*domain.UserAppRole
	saveCalled     bool
}

func (f *fakeRoleRepo) Save(context.Context, *domain.Role) error { return nil }

func (f *fakeRoleRepo) FindByID(context.Context, shared.RoleID) (*domain.Role, error) {
	if f.findByIDErr != nil {
		return nil, f.findByIDErr
	}
	return f.role, nil
}

func (f *fakeRoleRepo) FindByName(context.Context, shared.AppID, shared.TenantID, string) (*domain.Role, error) {
	return nil, domain.ErrRoleNotFound
}

func (f *fakeRoleRepo) FindByUserAndApp(context.Context, shared.UserID, shared.AppID) ([]*domain.Role, error) {
	return nil, nil
}

func (f *fakeRoleRepo) ListByApp(context.Context, shared.AppID) ([]*domain.Role, error) {
	return nil, nil
}

func (f *fakeRoleRepo) Delete(context.Context, shared.RoleID) error { return nil }

func (f *fakeRoleRepo) SaveUserAppRole(context.Context, *domain.UserAppRole) error {
	f.saveCalled = true
	return nil
}

func (f *fakeRoleRepo) DeleteUserAppRole(context.Context, shared.UserID, shared.AppID, shared.RoleID) (bool, error) {
	return true, nil
}

func (f *fakeRoleRepo) FindUserAppRoles(context.Context, shared.UserID, shared.AppID) ([]*domain.UserAppRole, error) {
	return f.userAssignments, nil
}

type fakeEventBus struct {
	published int
}

func (f *fakeEventBus) Publish(context.Context, ...shared.DomainEvent) error {
	f.published++
	return nil
}

func (f *fakeEventBus) Subscribe(string, shared.EventHandler) error { return nil }

type fakeTx struct{}

func (f *fakeTx) Execute(ctx context.Context, fn func(txCtx context.Context) error) error {
	return fn(ctx)
}

func TestAssignRole_RejectsCrossAppRole(t *testing.T) {
	targetAppID := shared.NewAppID()
	role := domain.NewRole(shared.NewAppID(), shared.NewTenantID(), "r", "")
	repo := &fakeRoleRepo{role: role}
	svc := &AuthzAppService{
		roleRepo:  repo,
		eventBus:  &fakeEventBus{},
		txManager: &fakeTx{},
	}

	err := svc.AssignRole(context.Background(), &command.AssignRole{
		UserID:   shared.NewUserID().String(),
		AppID:    targetAppID.String(),
		RoleID:   role.ID.String(),
		TenantID: shared.NewTenantID().String(),
	})
	if err != domain.ErrRoleAppMismatch {
		t.Fatalf("unexpected error: got %v want %v", err, domain.ErrRoleAppMismatch)
	}
	if repo.saveCalled {
		t.Fatalf("assignment should not be saved on app mismatch")
	}
}

func TestAssignRole_IdempotentWhenAlreadyAssigned(t *testing.T) {
	appID := shared.NewAppID()
	role := domain.NewRole(appID, shared.NewTenantID(), "r", "")
	userID := shared.NewUserID()
	repo := &fakeRoleRepo{
		role: role,
		userAssignments: []*domain.UserAppRole{
			{
				UserID: userID,
				AppID:  appID,
				RoleID: role.ID,
			},
		},
	}
	bus := &fakeEventBus{}
	svc := &AuthzAppService{
		roleRepo:  repo,
		eventBus:  bus,
		txManager: &fakeTx{},
	}

	err := svc.AssignRole(context.Background(), &command.AssignRole{
		UserID:   userID.String(),
		AppID:    appID.String(),
		RoleID:   role.ID.String(),
		TenantID: shared.NewTenantID().String(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.saveCalled {
		t.Fatalf("existing assignment should not be saved again")
	}
	if bus.published != 0 {
		t.Fatalf("existing assignment should not publish duplicate event")
	}
}

func TestAssignRole_InvalidInput(t *testing.T) {
	role := domain.NewRole(shared.NewAppID(), shared.NewTenantID(), "r", "")
	svc := &AuthzAppService{
		roleRepo:  &fakeRoleRepo{role: role},
		eventBus:  &fakeEventBus{},
		txManager: &fakeTx{},
	}

	err := svc.AssignRole(context.Background(), &command.AssignRole{
		UserID:   "",
		AppID:    shared.NewAppID().String(),
		RoleID:   role.ID.String(),
		TenantID: shared.NewTenantID().String(),
	})
	if err != shared.ErrInvalidInput {
		t.Fatalf("unexpected error: got %v want %v", err, shared.ErrInvalidInput)
	}
}

func TestCreateRole_InvalidInput(t *testing.T) {
	svc := &AuthzAppService{
		roleRepo:  &fakeRoleRepo{},
		eventBus:  &fakeEventBus{},
		txManager: &fakeTx{},
	}

	_, err := svc.CreateRole(context.Background(), &command.CreateRole{
		AppID:    "",
		TenantID: shared.NewTenantID().String(),
		Name:     "reviewer",
	})
	if err != shared.ErrInvalidInput {
		t.Fatalf("unexpected error: got %v want %v", err, shared.ErrInvalidInput)
	}

	_, err = svc.CreateRole(context.Background(), &command.CreateRole{
		AppID:    shared.NewAppID().String(),
		TenantID: shared.NewTenantID().String(),
		Name:     "   ",
	})
	if err != shared.ErrInvalidInput {
		t.Fatalf("unexpected error: got %v want %v", err, shared.ErrInvalidInput)
	}
}
