package application

import (
	"context"
	"testing"

	"openiam/internal/identity/application/command"
	"openiam/internal/identity/application/query"
	"openiam/internal/identity/domain"
	shared "openiam/internal/shared/domain"
)

type fakeUserRepo struct {
	existsByEmail bool
	saved         *domain.User
	findByEmail   *domain.User
	findByID      *domain.User
}

func (f *fakeUserRepo) Save(_ context.Context, user *domain.User) error {
	f.saved = user
	return nil
}

func (f *fakeUserRepo) FindByID(context.Context, shared.UserID) (*domain.User, error) {
	if f.findByID != nil {
		return f.findByID, nil
	}
	return nil, shared.ErrNotFound
}

func (f *fakeUserRepo) FindByEmail(context.Context, shared.TenantID, domain.Email) (*domain.User, error) {
	if f.findByEmail != nil {
		return f.findByEmail, nil
	}
	return nil, shared.ErrNotFound
}

func (f *fakeUserRepo) ExistsByEmail(context.Context, shared.TenantID, domain.Email) (bool, error) {
	return f.existsByEmail, nil
}

type fakeEventBus struct {
	published []shared.DomainEvent
}

func (f *fakeEventBus) Publish(_ context.Context, events ...shared.DomainEvent) error {
	f.published = append(f.published, events...)
	return nil
}

func (f *fakeEventBus) Subscribe(string, shared.EventHandler) error { return nil }

type fakeTxManager struct {
	executed bool
}

func (f *fakeTxManager) Execute(ctx context.Context, fn func(txCtx context.Context) error) error {
	f.executed = true
	return fn(ctx)
}

func TestIdentityService_RegisterUser_EmailAlreadyTaken(t *testing.T) {
	repo := &fakeUserRepo{existsByEmail: true}
	svc := NewIdentityService(repo, &fakeEventBus{}, &fakeTxManager{})

	_, err := svc.RegisterUser(context.Background(), &command.RegisterUser{
		AppID:    shared.NewAppID().String(),
		Email:    "alice@example.com",
		Password: "password123",
		TenantID: shared.NewTenantID().String(),
	})
	if err != domain.ErrEmailAlreadyTaken {
		t.Fatalf("unexpected error: got %v want %v", err, domain.ErrEmailAlreadyTaken)
	}
}

func TestIdentityService_RegisterUser_DefaultsProviderAndPublishesEvent(t *testing.T) {
	repo := &fakeUserRepo{}
	bus := &fakeEventBus{}
	tx := &fakeTxManager{}
	svc := NewIdentityService(repo, bus, tx)
	tenantID := shared.NewTenantID().String()
	appID := shared.NewAppID().String()

	userID, err := svc.RegisterUser(context.Background(), &command.RegisterUser{
		AppID:    appID,
		Email:    "alice@example.com",
		Password: "password123",
		TenantID: tenantID,
		Provider: "",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if userID == "" {
		t.Fatal("user id should not be empty")
	}
	if !tx.executed {
		t.Fatal("expected tx manager execution")
	}
	if repo.saved == nil {
		t.Fatal("user should be saved")
	}
	if len(bus.published) != 1 {
		t.Fatalf("expected one published event, got %d", len(bus.published))
	}

	evt, ok := bus.published[0].(domain.UserRegisteredEvent)
	if !ok {
		t.Fatalf("unexpected event type: %T", bus.published[0])
	}
	if evt.Provider != "password" {
		t.Fatalf("expected default provider password, got %q", evt.Provider)
	}
}

func TestIdentityService_RegisterExternalUser_ReturnsExistingUser(t *testing.T) {
	existing := domain.NewExternalUser(shared.NewTenantID(), shared.NewAppID(), "siwe", "0xabc", "pk")
	repo := &fakeUserRepo{findByEmail: existing}
	svc := NewIdentityService(repo, &fakeEventBus{}, &fakeTxManager{})

	userID, err := svc.RegisterExternalUser(context.Background(), &command.RegisterExternalUser{
		AppID:             shared.NewAppID().String(),
		TenantID:          shared.NewTenantID().String(),
		Provider:          "siwe",
		CredentialSubject: "0xabc",
		PublicKey:         "pk",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if userID != existing.ID {
		t.Fatalf("expected existing user id, got %q want %q", userID, existing.ID)
	}
	if repo.saved != nil {
		t.Fatalf("existing user path should not save new user")
	}
}

func TestIdentityService_RegisterExternalUser_DefaultTenantAndPublishes(t *testing.T) {
	repo := &fakeUserRepo{}
	bus := &fakeEventBus{}
	tx := &fakeTxManager{}
	svc := NewIdentityService(repo, bus, tx)

	userID, err := svc.RegisterExternalUser(context.Background(), &command.RegisterExternalUser{
		AppID:             shared.NewAppID().String(),
		TenantID:          "",
		Provider:          "webauthn",
		CredentialSubject: "cred-subject",
		PublicKey:         "pk",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if userID == "" {
		t.Fatal("user id should not be empty")
	}
	if !tx.executed {
		t.Fatal("expected tx manager execution")
	}
	if repo.saved == nil {
		t.Fatal("user should be saved")
	}
	if repo.saved.TenantID != shared.TenantID("default") {
		t.Fatalf("expected default tenant, got %q", repo.saved.TenantID)
	}
	if len(bus.published) != 1 {
		t.Fatalf("expected one published event, got %d", len(bus.published))
	}
}

func TestIdentityService_ChangePasswordAndPublish(t *testing.T) {
	email := domain.NewEmailFromTrusted("alice@example.com")
	tenantID := shared.NewTenantID()
	appID := shared.NewAppID()
	user, err := domain.NewUser(email, "oldPassword123", tenantID, appID, "password")
	if err != nil {
		t.Fatalf("create user failed: %v", err)
	}
	_ = user.PullEvents()

	repo := &fakeUserRepo{findByID: user}
	bus := &fakeEventBus{}
	tx := &fakeTxManager{}
	svc := NewIdentityService(repo, bus, tx)

	err = svc.ChangePassword(context.Background(), &command.ChangePassword{
		UserID:      user.ID.String(),
		OldPassword: "oldPassword123",
		NewPassword: "newPassword123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.saved == nil {
		t.Fatal("user should be saved after password change")
	}
	if !repo.saved.Password.Verify("newPassword123") {
		t.Fatalf("password should be updated")
	}
	if len(bus.published) != 1 {
		t.Fatalf("expected one event, got %d", len(bus.published))
	}
}

func TestIdentityService_GetUserAndFindByEmail(t *testing.T) {
	email := domain.NewEmailFromTrusted("alice@example.com")
	tenantID := shared.NewTenantID()
	appID := shared.NewAppID()
	user, err := domain.NewUser(email, "password123", tenantID, appID, "password")
	if err != nil {
		t.Fatalf("create user failed: %v", err)
	}
	user.Profile.DisplayName = "Alice"

	repo := &fakeUserRepo{findByID: user, findByEmail: user}
	svc := NewIdentityService(repo, &fakeEventBus{}, &fakeTxManager{})

	dto, err := svc.GetUser(context.Background(), &query.GetUser{UserID: user.ID.String()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dto == nil || dto.ID != user.ID.String() || dto.DisplayName != "Alice" {
		t.Fatalf("get user dto mismatch")
	}

	byEmail, err := svc.FindByEmail(context.Background(), tenantID, "alice@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if byEmail == nil || byEmail.ID != user.ID.String() {
		t.Fatalf("find by email dto mismatch")
	}
}
