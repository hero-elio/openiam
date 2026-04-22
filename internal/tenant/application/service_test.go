package application

import (
	"context"
	"errors"
	"testing"

	shared "openiam/internal/shared/domain"
	"openiam/internal/tenant/application/command"
	"openiam/internal/tenant/application/query"
	"openiam/internal/tenant/domain"
)

type fakeTenantRepo struct {
	saved          *domain.Tenant
	tenant         *domain.Tenant
	tenants        []*domain.Tenant
	lastListFilter domain.ListTenantsFilter
	saveErr        error
	findErr        error
	listErr        error
}

func (f *fakeTenantRepo) Save(_ context.Context, t *domain.Tenant) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.saved = t
	if f.tenant == nil {
		f.tenant = t
	}
	return nil
}

func (f *fakeTenantRepo) FindByID(_ context.Context, id shared.TenantID) (*domain.Tenant, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	if f.tenant != nil && f.tenant.ID == id {
		return f.tenant, nil
	}
	return nil, shared.ErrNotFound
}

func (f *fakeTenantRepo) List(_ context.Context, filter domain.ListTenantsFilter) ([]*domain.Tenant, error) {
	f.lastListFilter = filter
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.tenants, nil
}

type fakeAppRepo struct {
	saved *domain.Application
	app   *domain.Application
	apps  []*domain.Application
	saveErr error
	findErr error
	listErr error
}

func (f *fakeAppRepo) Save(_ context.Context, app *domain.Application) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.saved = app
	return nil
}

func (f *fakeAppRepo) FindByID(_ context.Context, id shared.AppID) (*domain.Application, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	if f.app != nil && f.app.ID == id {
		return f.app, nil
	}
	return nil, shared.ErrNotFound
}

func (f *fakeAppRepo) FindByClientID(context.Context, string) (*domain.Application, error) { return nil, nil }

func (f *fakeAppRepo) ListByTenant(context.Context, shared.TenantID) ([]*domain.Application, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.apps, nil
}

type fakeEventBus struct {
	published []shared.DomainEvent
	publishErr error
}

func (f *fakeEventBus) Publish(_ context.Context, events ...shared.DomainEvent) error {
	if f.publishErr != nil {
		return f.publishErr
	}
	f.published = append(f.published, events...)
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

func TestTenantAppService_CreateTenant(t *testing.T) {
	tenantRepo := &fakeTenantRepo{}
	svc := NewTenantAppService(tenantRepo, &fakeAppRepo{}, &fakeEventBus{}, &fakeTxManager{})

	tenantID, err := svc.CreateTenant(context.Background(), &command.CreateTenant{Name: "  acme  "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tenantID == "" {
		t.Fatal("tenant id should not be empty")
	}
	if tenantRepo.saved == nil || tenantRepo.saved.Name != "acme" {
		t.Fatalf("tenant name should be trimmed and saved")
	}
}

func TestTenantAppService_CreateApplication(t *testing.T) {
	tenant := domain.NewTenant("acme")
	tenantRepo := &fakeTenantRepo{tenant: tenant}
	appRepo := &fakeAppRepo{}
	bus := &fakeEventBus{}
	tx := &fakeTxManager{}
	svc := NewTenantAppService(tenantRepo, appRepo, bus, tx)

	res, err := svc.CreateApplication(context.Background(), &command.CreateApplication{
		TenantID:  tenant.ID.String(),
		Name:      "portal",
		CreatedBy: shared.NewUserID().String(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !tx.executed {
		t.Fatal("expected tx manager execution")
	}
	if appRepo.saved == nil {
		t.Fatal("application should be saved")
	}
	if res.ClientSecret == "" {
		t.Fatal("client secret should be returned for one-time display")
	}
	if len(bus.published) != 1 {
		t.Fatalf("expected one published event, got %d", len(bus.published))
	}
}

func TestTenantAppService_UpdateApplication(t *testing.T) {
	tenantID := shared.NewTenantID()
	app := domain.NewApplication(
		tenantID,
		"old-name",
		domain.GenerateClientCredentials(),
		shared.NewUserID(),
	)
	app.RedirectURIs = []string{"https://old/callback"}
	app.Scopes = []string{"old:scope"}

	appRepo := &fakeAppRepo{app: app}
	svc := NewTenantAppService(&fakeTenantRepo{}, appRepo, &fakeEventBus{}, &fakeTxManager{})

	err := svc.UpdateApplication(context.Background(), &command.UpdateApplication{
		AppID:        app.ID.String(),
		Name:         "new-name",
		RedirectURIs: []string{"https://new/callback"},
		Scopes:       []string{"openid", "profile"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if appRepo.saved == nil {
		t.Fatal("updated app should be saved")
	}
	if appRepo.saved.Name != "new-name" {
		t.Fatalf("name not updated: got %q", appRepo.saved.Name)
	}
	if len(appRepo.saved.RedirectURIs) != 1 || appRepo.saved.RedirectURIs[0] != "https://new/callback" {
		t.Fatalf("redirect uris not updated")
	}
	if len(appRepo.saved.Scopes) != 2 || appRepo.saved.Scopes[0] != "openid" {
		t.Fatalf("scopes not updated")
	}
}

func TestTenantAppService_GetTenant(t *testing.T) {
	tenant := domain.NewTenant("acme")
	svc := NewTenantAppService(&fakeTenantRepo{tenant: tenant}, &fakeAppRepo{}, &fakeEventBus{}, &fakeTxManager{})

	dto, err := svc.GetTenant(context.Background(), &query.GetTenant{TenantID: tenant.ID.String()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dto == nil || dto.ID != tenant.ID.String() || dto.Name != "acme" {
		t.Fatalf("tenant dto mismatch")
	}
}

func TestTenantAppService_ListTenants(t *testing.T) {
	t1 := domain.NewTenant("acme")
	t2 := domain.NewTenant("globex")
	tenantRepo := &fakeTenantRepo{tenants: []*domain.Tenant{t1, t2}}
	svc := NewTenantAppService(tenantRepo, &fakeAppRepo{}, &fakeEventBus{}, &fakeTxManager{})

	got, err := svc.ListTenants(context.Background(), &query.ListTenants{Limit: 50, Offset: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 tenants, got %d", len(got))
	}
	if tenantRepo.lastListFilter.Limit != 50 || tenantRepo.lastListFilter.Offset != 10 {
		t.Fatalf("paging params not forwarded: %+v", tenantRepo.lastListFilter)
	}
}

func TestTenantAppService_GetAndListApplications(t *testing.T) {
	tenantID := shared.NewTenantID()
	app1 := domain.NewApplication(tenantID, "portal", domain.GenerateClientCredentials(), shared.NewUserID())
	app2 := domain.NewApplication(tenantID, "admin", domain.GenerateClientCredentials(), shared.NewUserID())
	appRepo := &fakeAppRepo{app: app1, apps: []*domain.Application{app1, app2}}
	svc := NewTenantAppService(&fakeTenantRepo{}, appRepo, &fakeEventBus{}, &fakeTxManager{})

	got, err := svc.GetApplication(context.Background(), &query.GetApplication{AppID: app1.ID.String()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.ID != app1.ID.String() || got.Name != "portal" {
		t.Fatalf("get application dto mismatch")
	}

	list, err := svc.ListApplications(context.Background(), &query.ListApplications{TenantID: tenantID.String()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 applications, got %d", len(list))
	}
}

func TestTenantAppService_ExceptionBoundaries(t *testing.T) {
	t.Run("create tenant invalid input", func(t *testing.T) {
		svc := NewTenantAppService(&fakeTenantRepo{}, &fakeAppRepo{}, &fakeEventBus{}, &fakeTxManager{})
		_, err := svc.CreateTenant(context.Background(), &command.CreateTenant{Name: "   "})
		if !errors.Is(err, shared.ErrInvalidInput) {
			t.Fatalf("expected invalid input, got %v", err)
		}
	})

	t.Run("create tenant tx failure", func(t *testing.T) {
		txErr := errors.New("tx failed")
		svc := NewTenantAppService(&fakeTenantRepo{}, &fakeAppRepo{}, &fakeEventBus{}, &fakeTxManager{executeErr: txErr})
		_, err := svc.CreateTenant(context.Background(), &command.CreateTenant{Name: "acme"})
		if !errors.Is(err, txErr) {
			t.Fatalf("expected tx error passthrough, got %v", err)
		}
	})

	t.Run("create application tenant not found", func(t *testing.T) {
		svc := NewTenantAppService(&fakeTenantRepo{}, &fakeAppRepo{}, &fakeEventBus{}, &fakeTxManager{})
		_, err := svc.CreateApplication(context.Background(), &command.CreateApplication{
			TenantID: shared.NewTenantID().String(),
			Name:     "portal",
		})
		if !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("expected tenant lookup error, got %v", err)
		}
	})

	t.Run("create application invalid input", func(t *testing.T) {
		svc := NewTenantAppService(&fakeTenantRepo{}, &fakeAppRepo{}, &fakeEventBus{}, &fakeTxManager{})
		_, err := svc.CreateApplication(context.Background(), &command.CreateApplication{
			TenantID: "",
			Name:     "portal",
		})
		if !errors.Is(err, shared.ErrInvalidInput) {
			t.Fatalf("expected invalid input, got %v", err)
		}

		_, err = svc.CreateApplication(context.Background(), &command.CreateApplication{
			TenantID: shared.NewTenantID().String(),
			Name:     "   ",
		})
		if !errors.Is(err, shared.ErrInvalidInput) {
			t.Fatalf("expected invalid input, got %v", err)
		}
	})

	t.Run("create application save error", func(t *testing.T) {
		tenant := domain.NewTenant("acme")
		saveErr := errors.New("save app failed")
		svc := NewTenantAppService(
			&fakeTenantRepo{tenant: tenant},
			&fakeAppRepo{saveErr: saveErr},
			&fakeEventBus{},
			&fakeTxManager{},
		)
		_, err := svc.CreateApplication(context.Background(), &command.CreateApplication{
			TenantID: tenant.ID.String(),
			Name:     "portal",
		})
		if !errors.Is(err, saveErr) {
			t.Fatalf("expected app save error passthrough, got %v", err)
		}
	})

	t.Run("create application publish error", func(t *testing.T) {
		tenant := domain.NewTenant("acme")
		pubErr := errors.New("publish failed")
		svc := NewTenantAppService(
			&fakeTenantRepo{tenant: tenant},
			&fakeAppRepo{},
			&fakeEventBus{publishErr: pubErr},
			&fakeTxManager{},
		)
		_, err := svc.CreateApplication(context.Background(), &command.CreateApplication{
			TenantID: tenant.ID.String(),
			Name:     "portal",
		})
		if !errors.Is(err, pubErr) {
			t.Fatalf("expected publish error passthrough, got %v", err)
		}
	})

	t.Run("update application not found", func(t *testing.T) {
		svc := NewTenantAppService(&fakeTenantRepo{}, &fakeAppRepo{}, &fakeEventBus{}, &fakeTxManager{})
		err := svc.UpdateApplication(context.Background(), &command.UpdateApplication{AppID: shared.NewAppID().String(), Name: "x"})
		if !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("expected app lookup error, got %v", err)
		}
	})

	t.Run("update application invalid input", func(t *testing.T) {
		svc := NewTenantAppService(&fakeTenantRepo{}, &fakeAppRepo{}, &fakeEventBus{}, &fakeTxManager{})
		err := svc.UpdateApplication(context.Background(), &command.UpdateApplication{
			AppID: "",
			Name:  "new",
		})
		if !errors.Is(err, shared.ErrInvalidInput) {
			t.Fatalf("expected invalid input for empty app id, got %v", err)
		}

		err = svc.UpdateApplication(context.Background(), &command.UpdateApplication{
			AppID: shared.NewAppID().String(),
			Name:  "   ",
		})
		if !errors.Is(err, shared.ErrInvalidInput) {
			t.Fatalf("expected invalid input for blank name, got %v", err)
		}
	})

	t.Run("update application keeps fields when nil slices", func(t *testing.T) {
		tenantID := shared.NewTenantID()
		app := domain.NewApplication(tenantID, "old-name", domain.GenerateClientCredentials(), shared.NewUserID())
		app.RedirectURIs = []string{"https://old/callback"}
		app.Scopes = []string{"scope:old"}

		bus := &fakeEventBus{}
		appRepo := &fakeAppRepo{app: app}
		svc := NewTenantAppService(&fakeTenantRepo{}, appRepo, bus, &fakeTxManager{})
		err := svc.UpdateApplication(context.Background(), &command.UpdateApplication{
			AppID: app.ID.String(),
			Name:  "   ",
		})
		if !errors.Is(err, shared.ErrInvalidInput) {
			t.Fatalf("expected invalid input for blank-only name, got %v", err)
		}

		err = svc.UpdateApplication(context.Background(), &command.UpdateApplication{
			AppID: app.ID.String(),
			Name:  "",
		})
		if err != nil {
			t.Fatalf("unexpected error for empty name(no update): %v", err)
		}
		// No fields changed → no save, no event, original aggregate untouched.
		if appRepo.saved != nil {
			t.Fatalf("expected no save when nothing changed, got %+v", appRepo.saved)
		}
		if len(bus.published) != 0 {
			t.Fatalf("expected no event when nothing changed, got %d", len(bus.published))
		}
		if app.Name != "old-name" {
			t.Fatalf("name should remain unchanged when empty name provided, got %q", app.Name)
		}
		if len(app.RedirectURIs) != 1 || app.RedirectURIs[0] != "https://old/callback" {
			t.Fatalf("redirect uris should remain unchanged when nil")
		}
		if len(app.Scopes) != 1 || app.Scopes[0] != "scope:old" {
			t.Fatalf("scopes should remain unchanged when nil")
		}
	})

	t.Run("update application emits ApplicationUpdated and saves", func(t *testing.T) {
		tenantID := shared.NewTenantID()
		app := domain.NewApplication(tenantID, "old-name", domain.GenerateClientCredentials(), shared.NewUserID())
		// Drain the creation event so we can assert the update event in isolation.
		_ = app.PullEvents()

		bus := &fakeEventBus{}
		appRepo := &fakeAppRepo{app: app}
		svc := NewTenantAppService(&fakeTenantRepo{}, appRepo, bus, &fakeTxManager{})

		if err := svc.UpdateApplication(context.Background(), &command.UpdateApplication{
			AppID:        app.ID.String(),
			Name:         "new-name",
			RedirectURIs: []string{"https://new/cb"},
			Scopes:       []string{"scope:new"},
		}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if appRepo.saved == nil || appRepo.saved.Name != "new-name" {
			t.Fatalf("expected app saved with new name, got %+v", appRepo.saved)
		}
		if len(bus.published) != 1 {
			t.Fatalf("expected one published event, got %d", len(bus.published))
		}
		if bus.published[0].EventName() != domain.EventApplicationUpdated {
			t.Fatalf("expected %q event, got %q", domain.EventApplicationUpdated, bus.published[0].EventName())
		}
	})

	t.Run("get/list passthrough repository error", func(t *testing.T) {
		findErr := errors.New("find tenant failed")
		listErr := errors.New("list apps failed")
		svcGet := NewTenantAppService(&fakeTenantRepo{findErr: findErr}, &fakeAppRepo{}, &fakeEventBus{}, &fakeTxManager{})
		if _, err := svcGet.GetTenant(context.Background(), &query.GetTenant{TenantID: shared.NewTenantID().String()}); !errors.Is(err, findErr) {
			t.Fatalf("expected get tenant error passthrough, got %v", err)
		}

		svcList := NewTenantAppService(&fakeTenantRepo{}, &fakeAppRepo{listErr: listErr}, &fakeEventBus{}, &fakeTxManager{})
		if _, err := svcList.ListApplications(context.Background(), &query.ListApplications{TenantID: shared.NewTenantID().String()}); !errors.Is(err, listErr) {
			t.Fatalf("expected list applications error passthrough, got %v", err)
		}
	})
}
