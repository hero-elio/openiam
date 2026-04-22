package event

import (
	"context"
	"errors"
	"testing"
	"time"

	authzDomain "openiam/internal/authz/domain"
	shared "openiam/internal/shared/domain"
)

type fakeRoleRepo struct {
	byName       map[string]*authzDomain.Role
	savedRoles   []*authzDomain.Role
	savedUserApp []*authzDomain.UserAppRole
	saveUARErr   error
	saveRoleErr  error
	findByNameErr error
}

func newFakeRoleRepo() *fakeRoleRepo {
	return &fakeRoleRepo{byName: make(map[string]*authzDomain.Role)}
}

func roleKey(appID shared.AppID, name string) string {
	return appID.String() + ":" + name
}

func (f *fakeRoleRepo) Save(_ context.Context, role *authzDomain.Role) error {
	if f.saveRoleErr != nil {
		return f.saveRoleErr
	}
	f.savedRoles = append(f.savedRoles, role)
	f.byName[roleKey(role.AppID, role.Name)] = role
	return nil
}

func (f *fakeRoleRepo) FindByID(context.Context, shared.RoleID) (*authzDomain.Role, error) {
	return nil, shared.ErrNotFound
}

func (f *fakeRoleRepo) FindByName(_ context.Context, appID shared.AppID, _ shared.TenantID, name string) (*authzDomain.Role, error) {
	if f.findByNameErr != nil {
		return nil, f.findByNameErr
	}
	role := f.byName[roleKey(appID, name)]
	if role == nil {
		return nil, authzDomain.ErrRoleNotFound
	}
	return role, nil
}

func (f *fakeRoleRepo) FindByUserAndApp(context.Context, shared.UserID, shared.AppID) ([]*authzDomain.Role, error) {
	return nil, nil
}

func (f *fakeRoleRepo) ListByApp(context.Context, shared.AppID) ([]*authzDomain.Role, error) {
	return nil, nil
}

func (f *fakeRoleRepo) Delete(context.Context, shared.RoleID) error { return nil }

func (f *fakeRoleRepo) SaveUserAppRole(_ context.Context, uar *authzDomain.UserAppRole) error {
	if f.saveUARErr != nil {
		return f.saveUARErr
	}
	f.savedUserApp = append(f.savedUserApp, uar)
	return nil
}

func (f *fakeRoleRepo) DeleteUserAppRole(context.Context, shared.UserID, shared.AppID, shared.RoleID) (bool, error) {
	return true, nil
}

func (f *fakeRoleRepo) FindUserAppRoles(context.Context, shared.UserID, shared.AppID) ([]*authzDomain.UserAppRole, error) {
	return nil, nil
}

func (f *fakeRoleRepo) ListUserAppRolesByRole(context.Context, shared.RoleID) ([]*authzDomain.UserAppRole, error) {
	return nil, nil
}

type fakeTemplateProvider struct {
	roles []*authzDomain.Role
	err   error
}

func (f *fakeTemplateProvider) FindTemplates(context.Context, shared.TenantID) ([]*authzDomain.Role, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.roles, nil
}

type fakePermDefRepo struct {
	upserted []*authzDomain.PermissionDefinition
	upsertErr error
}

func (f *fakePermDefRepo) Upsert(_ context.Context, pd *authzDomain.PermissionDefinition) error {
	if f.upsertErr != nil {
		return f.upsertErr
	}
	f.upserted = append(f.upserted, pd)
	return nil
}

func (f *fakePermDefRepo) Delete(context.Context, shared.AppID, string, string) error { return nil }

func (f *fakePermDefRepo) ListByApp(context.Context, shared.AppID) ([]*authzDomain.PermissionDefinition, error) {
	return nil, nil
}

func (f *fakePermDefRepo) FindByKey(context.Context, shared.AppID, string, string) (*authzDomain.PermissionDefinition, error) {
	return nil, nil
}

type fakeEventBus struct{}

func (f *fakeEventBus) Publish(context.Context, ...shared.DomainEvent) error { return nil }

type fakeEventBusWithSubscribeErr struct {
	subscribed []string
	errByName  map[string]error
}

func (f *fakeEventBusWithSubscribeErr) Publish(context.Context, ...shared.DomainEvent) error { return nil }

func (f *fakeEventBusWithSubscribeErr) Subscribe(eventName string, _ shared.EventHandler) error {
	f.subscribed = append(f.subscribed, eventName)
	if f.errByName != nil {
		if err, ok := f.errByName[eventName]; ok {
			return err
		}
	}
	return nil
}

func (f *fakeEventBus) Subscribe(string, shared.EventHandler) error { return nil }

type fakeTxManager struct {
	executed bool
	executeErr error
}

func (f *fakeTxManager) Execute(ctx context.Context, fn func(txCtx context.Context) error) error {
	f.executed = true
	if f.executeErr != nil {
		return f.executeErr
	}
	return fn(ctx)
}

type fakeAppCreatedEvent struct {
	appID     shared.AppID
	tenantID  shared.TenantID
	createdBy shared.UserID
}

func (f fakeAppCreatedEvent) EventName() string     { return "application.created" }
func (f fakeAppCreatedEvent) OccurredAt() time.Time { return time.Now() }
func (f fakeAppCreatedEvent) AggregateID() string   { return f.appID.String() }
func (f fakeAppCreatedEvent) GetAppID() shared.AppID       { return f.appID }
func (f fakeAppCreatedEvent) GetTenantID() shared.TenantID { return f.tenantID }
func (f fakeAppCreatedEvent) GetCreatedBy() shared.UserID  { return f.createdBy }

type fakeUserRegisteredEvent struct {
	userID   shared.UserID
	appID    shared.AppID
	tenantID shared.TenantID
}

func (f fakeUserRegisteredEvent) EventName() string     { return "user.registered" }
func (f fakeUserRegisteredEvent) OccurredAt() time.Time { return time.Now() }
func (f fakeUserRegisteredEvent) AggregateID() string   { return f.userID.String() }
func (f fakeUserRegisteredEvent) GetUserID() shared.UserID       { return f.userID }
func (f fakeUserRegisteredEvent) GetAppID() shared.AppID         { return f.appID }
func (f fakeUserRegisteredEvent) GetTenantID() shared.TenantID   { return f.tenantID }

type fakeUnknownEvent struct{}

func (f fakeUnknownEvent) EventName() string     { return "unknown.event" }
func (f fakeUnknownEvent) OccurredAt() time.Time { return time.Now() }
func (f fakeUnknownEvent) AggregateID() string   { return "agg-1" }

func TestSubscriberOnApplicationCreated_AssignsCreatorRoleFromTemplate(t *testing.T) {
	roleRepo := newFakeRoleRepo()
	permRepo := &fakePermDefRepo{}
	txMgr := &fakeTxManager{}
	templateProv := &fakeTemplateProvider{
		roles: []*authzDomain.Role{
			{
				Name:                "owner",
				Description:         "owner",
				Permissions:         []authzDomain.Permission{authzDomain.NewPermission("*", "*")},
				IsTemplate:          true,
				IsSystem:            true,
				IsDefaultForCreator: true,
			},
			{
				Name:        "member",
				Description: "member",
				IsTemplate:  true,
				IsSystem:    true,
			},
		},
	}
	sub := NewSubscriber(roleRepo, templateProv, permRepo, &fakeEventBus{}, txMgr)

	appID := shared.NewAppID()
	tenantID := shared.NewTenantID()
	createdBy := shared.NewUserID()
	err := sub.onApplicationCreated(context.Background(), fakeAppCreatedEvent{
		appID:     appID,
		tenantID:  tenantID,
		createdBy: createdBy,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !txMgr.executed {
		t.Fatal("expected transaction manager execution")
	}
	if len(roleRepo.savedRoles) != 2 {
		t.Fatalf("expected 2 seeded roles, got %d", len(roleRepo.savedRoles))
	}
	if len(roleRepo.savedUserApp) != 1 {
		t.Fatalf("expected 1 creator role assignment, got %d", len(roleRepo.savedUserApp))
	}
	if roleRepo.savedUserApp[0].UserID != createdBy {
		t.Fatalf("creator assignment user mismatch")
	}
	if len(permRepo.upserted) != len(authzDomain.BuiltinPermissions) {
		t.Fatalf("builtin permission sync mismatch: got %d want %d", len(permRepo.upserted), len(authzDomain.BuiltinPermissions))
	}
}

func TestSubscriberOnApplicationCreated_TemplateProviderErrorPropagates(t *testing.T) {
	roleRepo := newFakeRoleRepo()
	permRepo := &fakePermDefRepo{}
	txMgr := &fakeTxManager{}
	templateProv := &fakeTemplateProvider{err: errors.New("db unavailable")}
	sub := NewSubscriber(roleRepo, templateProv, permRepo, &fakeEventBus{}, txMgr)

	err := sub.onApplicationCreated(context.Background(), fakeAppCreatedEvent{
		appID:    shared.NewAppID(),
		tenantID: shared.NewTenantID(),
	})
	if err == nil {
		t.Fatalf("expected template provider error")
	}
}

func TestSubscriberOnUserRegistered_AutoAssignsMemberRole(t *testing.T) {
	roleRepo := newFakeRoleRepo()
	appID := shared.NewAppID()
	memberRole := authzDomain.NewSystemRole(appID, shared.NewTenantID(), "member", "default member")
	roleRepo.byName[roleKey(appID, "member")] = memberRole
	sub := NewSubscriber(roleRepo, &fakeTemplateProvider{}, &fakePermDefRepo{}, &fakeEventBus{}, &fakeTxManager{})

	userID := shared.NewUserID()
	tenantID := shared.NewTenantID()
	err := sub.onUserRegistered(context.Background(), fakeUserRegisteredEvent{
		userID:   userID,
		appID:    appID,
		tenantID: tenantID,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roleRepo.savedUserApp) != 1 {
		t.Fatalf("expected one role assignment, got %d", len(roleRepo.savedUserApp))
	}
	uar := roleRepo.savedUserApp[0]
	if uar.UserID != userID || uar.AppID != appID || uar.RoleID != memberRole.ID || uar.TenantID != tenantID {
		t.Fatalf("assigned role payload mismatch")
	}
}

func TestSubscriberOnUserRegistered_MissingMemberRoleIsNoop(t *testing.T) {
	roleRepo := newFakeRoleRepo()
	sub := NewSubscriber(roleRepo, &fakeTemplateProvider{}, &fakePermDefRepo{}, &fakeEventBus{}, &fakeTxManager{})

	err := sub.onUserRegistered(context.Background(), fakeUserRegisteredEvent{
		userID:   shared.NewUserID(),
		appID:    shared.NewAppID(),
		tenantID: shared.NewTenantID(),
	})
	if err != nil {
		t.Fatalf("missing role should be noop, got error: %v", err)
	}
	if len(roleRepo.savedUserApp) != 0 {
		t.Fatalf("no assignment expected when member role missing")
	}
}

func TestSubscriberOnUserRegistered_FindRoleInfraErrorPropagates(t *testing.T) {
	roleRepo := newFakeRoleRepo()
	roleRepo.findByNameErr = errors.New("db unavailable")
	sub := NewSubscriber(roleRepo, &fakeTemplateProvider{}, &fakePermDefRepo{}, &fakeEventBus{}, &fakeTxManager{})

	err := sub.onUserRegistered(context.Background(), fakeUserRegisteredEvent{
		userID:   shared.NewUserID(),
		appID:    shared.NewAppID(),
		tenantID: shared.NewTenantID(),
	})
	if err == nil {
		t.Fatalf("expected infra error to propagate")
	}
}

func TestSubscriberOnUserRegistered_AssignErrorPropagates(t *testing.T) {
	roleRepo := newFakeRoleRepo()
	appID := shared.NewAppID()
	memberRole := authzDomain.NewSystemRole(appID, shared.NewTenantID(), "member", "default member")
	roleRepo.byName[roleKey(appID, "member")] = memberRole
	roleRepo.saveUARErr = errors.New("assign failed")
	sub := NewSubscriber(roleRepo, &fakeTemplateProvider{}, &fakePermDefRepo{}, &fakeEventBus{}, &fakeTxManager{})

	err := sub.onUserRegistered(context.Background(), fakeUserRegisteredEvent{
		userID:   shared.NewUserID(),
		appID:    appID,
		tenantID: shared.NewTenantID(),
	})
	if err == nil {
		t.Fatalf("expected assignment error")
	}
}

func TestSubscriberOnApplicationCreated_SyncPermissionsErrorPropagates(t *testing.T) {
	roleRepo := newFakeRoleRepo()
	permRepo := &fakePermDefRepo{upsertErr: errors.New("upsert failed")}
	txMgr := &fakeTxManager{}
	templateProv := &fakeTemplateProvider{
		roles: []*authzDomain.Role{
			{
				Name:       "member",
				IsTemplate: true,
			},
		},
	}
	sub := NewSubscriber(roleRepo, templateProv, permRepo, &fakeEventBus{}, txMgr)

	err := sub.onApplicationCreated(context.Background(), fakeAppCreatedEvent{
		appID:    shared.NewAppID(),
		tenantID: shared.NewTenantID(),
	})
	if err == nil {
		t.Fatalf("expected sync permission error")
	}
	if len(roleRepo.savedRoles) != 1 {
		t.Fatalf("role seed should still happen before permission sync error")
	}
}

func TestSubscriberOnApplicationCreated_UsesExistingCreatorRole(t *testing.T) {
	roleRepo := newFakeRoleRepo()
	permRepo := &fakePermDefRepo{}
	txMgr := &fakeTxManager{}
	appID := shared.NewAppID()
	tenantID := shared.NewTenantID()
	existingOwner := authzDomain.NewSystemRole(appID, tenantID, "owner", "existing")
	roleRepo.byName[roleKey(appID, "owner")] = existingOwner
	templateProv := &fakeTemplateProvider{
		roles: []*authzDomain.Role{
			{
				Name:                "owner",
				IsTemplate:          true,
				IsDefaultForCreator: true,
			},
		},
	}
	sub := NewSubscriber(roleRepo, templateProv, permRepo, &fakeEventBus{}, txMgr)

	createdBy := shared.NewUserID()
	err := sub.onApplicationCreated(context.Background(), fakeAppCreatedEvent{
		appID:     appID,
		tenantID:  tenantID,
		createdBy: createdBy,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roleRepo.savedRoles) != 0 {
		t.Fatalf("existing template role should be reused, no new role saved")
	}
	if len(roleRepo.savedUserApp) != 1 {
		t.Fatalf("creator should be assigned to existing creator-default role")
	}
	if roleRepo.savedUserApp[0].RoleID != existingOwner.ID {
		t.Fatalf("expected assignment to existing owner role")
	}
}

func TestSubscriberRegister_SubscribeErrorBoundary(t *testing.T) {
	t.Run("user.registered subscribe fails", func(t *testing.T) {
		subErr := errors.New("subscribe user failed")
		bus := &fakeEventBusWithSubscribeErr{errByName: map[string]error{"user.registered": subErr}}
		sub := NewSubscriber(newFakeRoleRepo(), &fakeTemplateProvider{}, &fakePermDefRepo{}, bus, &fakeTxManager{})

		err := sub.Register()
		if !errors.Is(err, subErr) {
			t.Fatalf("expected subscribe error passthrough, got %v", err)
		}
	})

	t.Run("application.created subscribe fails", func(t *testing.T) {
		subErr := errors.New("subscribe app failed")
		bus := &fakeEventBusWithSubscribeErr{errByName: map[string]error{"application.created": subErr}}
		sub := NewSubscriber(newFakeRoleRepo(), &fakeTemplateProvider{}, &fakePermDefRepo{}, bus, &fakeTxManager{})

		err := sub.Register()
		if !errors.Is(err, subErr) {
			t.Fatalf("expected subscribe error passthrough, got %v", err)
		}
		if len(bus.subscribed) != 2 {
			t.Fatalf("expected two subscribe attempts, got %d", len(bus.subscribed))
		}
	})
}

func TestSubscriber_EventTypeMismatchIsNoop(t *testing.T) {
	sub := NewSubscriber(newFakeRoleRepo(), &fakeTemplateProvider{}, &fakePermDefRepo{}, &fakeEventBus{}, &fakeTxManager{})

	if err := sub.onUserRegistered(context.Background(), fakeUnknownEvent{}); err != nil {
		t.Fatalf("unexpected error for mismatched user event type: %v", err)
	}
	if err := sub.onApplicationCreated(context.Background(), fakeUnknownEvent{}); err != nil {
		t.Fatalf("unexpected error for mismatched app event type: %v", err)
	}
}

func TestSubscriberOnApplicationCreated_ErrorBoundaries(t *testing.T) {
	t.Run("tx manager error", func(t *testing.T) {
		txErr := errors.New("tx execute failed")
		sub := NewSubscriber(newFakeRoleRepo(), &fakeTemplateProvider{}, &fakePermDefRepo{}, &fakeEventBus{}, &fakeTxManager{executeErr: txErr})
		err := sub.onApplicationCreated(context.Background(), fakeAppCreatedEvent{
			appID:    shared.NewAppID(),
			tenantID: shared.NewTenantID(),
		})
		if !errors.Is(err, txErr) {
			t.Fatalf("expected tx error passthrough, got %v", err)
		}
	})

	t.Run("seed role save error", func(t *testing.T) {
		saveErr := errors.New("save role failed")
		roleRepo := newFakeRoleRepo()
		roleRepo.saveRoleErr = saveErr
		sub := NewSubscriber(roleRepo, &fakeTemplateProvider{
			roles: []*authzDomain.Role{{Name: "member", IsTemplate: true}},
		}, &fakePermDefRepo{}, &fakeEventBus{}, &fakeTxManager{})
		err := sub.onApplicationCreated(context.Background(), fakeAppCreatedEvent{
			appID:    shared.NewAppID(),
			tenantID: shared.NewTenantID(),
		})
		if !errors.Is(err, saveErr) {
			t.Fatalf("expected role save error passthrough, got %v", err)
		}
	})

	t.Run("creator assignment error", func(t *testing.T) {
		assignErr := errors.New("assign creator failed")
		roleRepo := newFakeRoleRepo()
		roleRepo.saveUARErr = assignErr
		sub := NewSubscriber(roleRepo, &fakeTemplateProvider{
			roles: []*authzDomain.Role{{Name: "owner", IsTemplate: true, IsDefaultForCreator: true}},
		}, &fakePermDefRepo{}, &fakeEventBus{}, &fakeTxManager{})
		err := sub.onApplicationCreated(context.Background(), fakeAppCreatedEvent{
			appID:     shared.NewAppID(),
			tenantID:  shared.NewTenantID(),
			createdBy: shared.NewUserID(),
		})
		if !errors.Is(err, assignErr) {
			t.Fatalf("expected creator assignment error passthrough, got %v", err)
		}
	})
}
