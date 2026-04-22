package e2e_test

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"openiam/internal/authz"
	authzCmd "openiam/internal/authz/application/command"
	authzQuery "openiam/internal/authz/application/query"
	authzDomain "openiam/internal/authz/domain"
	identity "openiam/internal/identity"
	identityCmd "openiam/internal/identity/application/command"
	shared "openiam/internal/shared/domain"
	"openiam/internal/shared/infra/eventbus"
	sharedPersistence "openiam/internal/shared/infra/persistence"
	tenant "openiam/internal/tenant"
	tenantCmd "openiam/internal/tenant/application/command"
)

func setupPostgres(t *testing.T) (dsn string, cleanup func()) {
	t.Helper()
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("iam_e2e"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("get connection string: %v", err)
	}

	return connStr, func() { _ = pgContainer.Terminate(ctx) }
}

func migrationDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "migration")
}

func runMigrations(t *testing.T, dsn string) {
	t.Helper()
	m, err := migrate.New("file://"+migrationDir(), dsn)
	if err != nil {
		t.Fatalf("create migrator: %v", err)
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("run migrations: %v", err)
	}
	srcErr, dbErr := m.Close()
	if srcErr != nil {
		t.Fatalf("close migration source: %v", srcErr)
	}
	if dbErr != nil {
		t.Fatalf("close migration db: %v", dbErr)
	}
}

func TestE2E_TenantAuthzIdentityFlow(t *testing.T) {
	dsn, cleanup := setupPostgres(t)
	defer cleanup()
	runMigrations(t, dsn)

	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		t.Fatalf("connect db: %v", err)
	}
	defer db.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	bus := eventbus.NewMemoryEventBus(logger)
	txMgr := sharedPersistence.NewTxManager(db)

	authorizer, err := authz.NewAuthorizer(db, bus, txMgr)
	if err != nil {
		t.Fatalf("init authz: %v", err)
	}
	tenantMgr := tenant.NewManager(db, bus, txMgr, nil)
	identityReg := identity.NewRegistry(db, bus, txMgr, nil, tenant.NewScopeAdapter(tenantMgr))

	ctx := context.Background()
	tenantID, err := tenantMgr.Service.CreateTenant(ctx, &tenantCmd.CreateTenant{Name: "acme"})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	creatorID := shared.NewUserID()
	appRes, err := tenantMgr.Service.CreateApplication(ctx, &tenantCmd.CreateApplication{
		TenantID:  tenantID.String(),
		Name:      "portal",
		CreatedBy: creatorID.String(),
	})
	if err != nil {
		t.Fatalf("create application: %v", err)
	}
	appID := appRes.Application.ID

	roles, err := authorizer.Service.ListRoles(ctx, &authzQuery.ListRoles{AppID: appID})
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	if len(roles) != 3 {
		t.Fatalf("expected 3 runtime roles, got %d", len(roles))
	}

	roleByID := make(map[string]string, len(roles))
	seen := map[string]bool{}
	for _, r := range roles {
		roleByID[r.ID] = r.Name
		seen[r.Name] = true
	}
	for _, expected := range []string{"super_admin", "admin", "member"} {
		if !seen[expected] {
			t.Fatalf("expected seeded role %q to exist", expected)
		}
	}

	creatorRoles, err := authorizer.Service.ListUserRoles(ctx, &authzQuery.ListUserRoles{
		UserID: creatorID.String(),
		AppID:  appID,
	})
	if err != nil {
		t.Fatalf("list creator roles: %v", err)
	}
	if len(creatorRoles) != 1 {
		t.Fatalf("expected creator to have 1 role, got %d", len(creatorRoles))
	}
	if roleByID[creatorRoles[0].RoleID] != "super_admin" {
		t.Fatalf("expected creator role super_admin, got %q", roleByID[creatorRoles[0].RoleID])
	}

	defs, err := authorizer.Service.ListPermissionDefinitions(ctx, &authzQuery.ListPermissionDefinitions{AppID: appID})
	if err != nil {
		t.Fatalf("list permission definitions: %v", err)
	}
	if len(defs) != len(authzDomain.BuiltinPermissions) {
		t.Fatalf("expected %d builtin permission definitions, got %d", len(authzDomain.BuiltinPermissions), len(defs))
	}

	allowed, err := authorizer.Service.CheckPermission(ctx, &authzQuery.CheckPermission{
		UserID:   creatorID.String(),
		AppID:    appID,
		Resource: authzDomain.ResourceUsers,
		Action:   authzDomain.ActionDelete,
	})
	if err != nil {
		t.Fatalf("check creator permission: %v", err)
	}
	if !allowed.Allowed {
		t.Fatalf("expected creator super_admin permission to be allowed")
	}

	memberUserID, err := identityReg.Service.RegisterExternalUser(ctx, &identityCmd.RegisterExternalUser{
		AppID:             appID,
		TenantID:          tenantID.String(),
		Provider:          "siwe",
		CredentialSubject: "eip155:1:0xabc",
		PublicKey:         "pk",
	})
	if err != nil {
		t.Fatalf("register external user: %v", err)
	}

	memberRoles, err := authorizer.Service.ListUserRoles(ctx, &authzQuery.ListUserRoles{
		UserID: memberUserID.String(),
		AppID:  appID,
	})
	if err != nil {
		t.Fatalf("list member roles: %v", err)
	}
	if len(memberRoles) != 1 {
		t.Fatalf("expected member user to have 1 role, got %d", len(memberRoles))
	}
	if roleByID[memberRoles[0].RoleID] != "member" {
		t.Fatalf("expected default assigned role member, got %q", roleByID[memberRoles[0].RoleID])
	}

	// 1) Register a custom permission definition (permission registry)
	if err := authorizer.Service.RegisterPermission(ctx, &authzCmd.RegisterPermission{
		AppID:       appID,
		Resource:    "documents",
		Action:      "approve",
		Description: "Approve document workflow",
	}); err != nil {
		t.Fatalf("register custom permission definition: %v", err)
	}

	defs, err = authorizer.Service.ListPermissionDefinitions(ctx, &authzQuery.ListPermissionDefinitions{AppID: appID})
	if err != nil {
		t.Fatalf("list permission definitions after register: %v", err)
	}
	var foundCustomDef bool
	for _, d := range defs {
		if d.Resource == "documents" && d.Action == "approve" && !d.IsBuiltin {
			foundCustomDef = true
			break
		}
	}
	if !foundCustomDef {
		t.Fatalf("expected custom permission definition documents:approve to exist")
	}

	// 2) Create a custom role
	customRoleID, err := authorizer.Service.CreateRole(ctx, &authzCmd.CreateRole{
		AppID:       appID,
		TenantID:    tenantID.String(),
		Name:        "reviewer",
		Description: "Document reviewer role",
	})
	if err != nil {
		t.Fatalf("create reviewer role: %v", err)
	}

	// 3) Grant permission to the role
	if err := authorizer.Service.GrantPermission(ctx, &authzCmd.GrantPermission{
		RoleID:   customRoleID.String(),
		Resource: "documents",
		Action:   "approve",
	}); err != nil {
		t.Fatalf("grant documents:approve to reviewer role: %v", err)
	}

	roles, err = authorizer.Service.ListRoles(ctx, &authzQuery.ListRoles{AppID: appID})
	if err != nil {
		t.Fatalf("list roles after custom role setup: %v", err)
	}
	var reviewerHasPerm bool
	for _, r := range roles {
		if r.ID == customRoleID.String() {
			for _, p := range r.Permissions {
				if p == "documents:approve" {
					reviewerHasPerm = true
					break
				}
			}
		}
	}
	if !reviewerHasPerm {
		t.Fatalf("expected reviewer role to contain documents:approve permission")
	}

	// 4) Assign the role to a user
	if err := authorizer.Service.AssignRole(ctx, &authzCmd.AssignRole{
		UserID:   memberUserID.String(),
		AppID:    appID,
		RoleID:   customRoleID.String(),
		TenantID: tenantID.String(),
	}); err != nil {
		t.Fatalf("assign reviewer role to member user: %v", err)
	}

	allowedViaRole, err := authorizer.Service.CheckPermission(ctx, &authzQuery.CheckPermission{
		UserID:   memberUserID.String(),
		AppID:    appID,
		Resource: "documents",
		Action:   "approve",
	})
	if err != nil {
		t.Fatalf("check permission via assigned role: %v", err)
	}
	if !allowedViaRole.Allowed {
		t.Fatalf("expected documents:approve to be allowed via assigned reviewer role")
	}

	// 5) Grant resource-level permission (ACL) to the user
	if err := authorizer.Service.GrantResourcePermission(ctx, &authzCmd.GrantResourcePermission{
		UserID:       memberUserID.String(),
		AppID:        appID,
		TenantID:     tenantID.String(),
		ResourceType: "invoice",
		ResourceID:   "inv-001",
		Action:       "read",
		GrantedBy:    creatorID.String(),
	}); err != nil {
		t.Fatalf("grant resource permission invoice:inv-001:read: %v", err)
	}

	allowedResource, err := authorizer.Service.CheckResourcePermission(ctx, &authzQuery.CheckResourcePermission{
		UserID:       memberUserID.String(),
		AppID:        appID,
		ResourceType: "invoice",
		ResourceID:   "inv-001",
		Action:       "read",
	})
	if err != nil {
		t.Fatalf("check resource permission after grant: %v", err)
	}
	if !allowedResource.Allowed {
		t.Fatalf("expected invoice inv-001 read to be allowed via resource-level grant")
	}

	aclList, err := authorizer.Service.ListResourcePermissions(ctx, &authzQuery.ListResourcePermissions{
		UserID: memberUserID.String(),
		AppID:  appID,
	})
	if err != nil {
		t.Fatalf("list resource permissions: %v", err)
	}
	var foundInvoiceACL bool
	for _, acl := range aclList {
		if acl.ResourceType == "invoice" && acl.ResourceID == "inv-001" && acl.Action == "read" {
			foundInvoiceACL = true
			break
		}
	}
	if !foundInvoiceACL {
		t.Fatalf("expected granted resource ACL to appear in list")
	}

	// 6) Reverse validation: permission should be denied after role permission revoke
	if err := authorizer.Service.RevokePermission(ctx, &authzCmd.RevokePermission{
		RoleID:   customRoleID.String(),
		Resource: "documents",
		Action:   "approve",
	}); err != nil {
		t.Fatalf("revoke documents:approve from reviewer role: %v", err)
	}

	deniedViaRole, err := authorizer.Service.CheckPermission(ctx, &authzQuery.CheckPermission{
		UserID:   memberUserID.String(),
		AppID:    appID,
		Resource: "documents",
		Action:   "approve",
	})
	if err != nil {
		t.Fatalf("check permission after role revoke: %v", err)
	}
	if deniedViaRole.Allowed {
		t.Fatalf("expected documents:approve to be denied after role permission revoke")
	}

	// 7) Reverse validation: ACL permission should be denied after revoke
	if err := authorizer.Service.RevokeResourcePermission(ctx, &authzCmd.RevokeResourcePermission{
		UserID:       memberUserID.String(),
		AppID:        appID,
		ResourceType: "invoice",
		ResourceID:   "inv-001",
		Action:       "read",
	}); err != nil {
		t.Fatalf("revoke resource permission invoice:inv-001:read: %v", err)
	}

	deniedResource, err := authorizer.Service.CheckResourcePermission(ctx, &authzQuery.CheckResourcePermission{
		UserID:       memberUserID.String(),
		AppID:        appID,
		ResourceType: "invoice",
		ResourceID:   "inv-001",
		Action:       "read",
	})
	if err != nil {
		t.Fatalf("check resource permission after revoke: %v", err)
	}
	if deniedResource.Allowed {
		t.Fatalf("expected invoice inv-001 read to be denied after ACL revoke")
	}
}
