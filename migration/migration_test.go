package migration_test

import (
	"context"
	"fmt"
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
)

func setupPostgres(t *testing.T) (dsn string, cleanup func()) {
	t.Helper()
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("iam_test"),
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
		pgContainer.Terminate(ctx)
		t.Fatalf("get connection string: %v", err)
	}

	return connStr, func() { pgContainer.Terminate(ctx) }
}

func migrationDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename))
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

func TestMigrations_AllTablesCreated(t *testing.T) {
	dsn, cleanup := setupPostgres(t)
	defer cleanup()

	runMigrations(t, dsn)

	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		t.Fatalf("connect db: %v", err)
	}
	defer db.Close()

	expectedTables := []string{
		"users",
		"credentials",
		"applications",
		"roles",
		"role_permissions",
		"user_app_roles",
		"domain_events",
	}

	for _, table := range expectedTables {
		var exists bool
		err := db.QueryRow(`
			SELECT EXISTS (
				SELECT FROM information_schema.tables
				WHERE table_schema = 'public' AND table_name = $1
			)`, table).Scan(&exists)
		if err != nil {
			t.Errorf("check table %s: %v", table, err)
			continue
		}
		if !exists {
			t.Errorf("table %s does not exist", table)
		}
	}
}

func TestMigrations_InsertExampleData(t *testing.T) {
	dsn, cleanup := setupPostgres(t)
	defer cleanup()

	runMigrations(t, dsn)

	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		t.Fatalf("connect db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	now := time.Now()

	tenantID := "00000000-0000-0000-0000-000000000001"
	userID := "00000000-0000-0000-0000-000000000002"
	appID := "00000000-0000-0000-0000-000000000003"
	roleID := "00000000-0000-0000-0000-000000000004"
	credID := "00000000-0000-0000-0000-000000000005"
	eventID := "00000000-0000-0000-0000-000000000006"

	// 1. users
	_, err = db.ExecContext(ctx, `
		INSERT INTO users (id, tenant_id, email, password_hash, display_name, status, version, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		userID, tenantID, "admin@example.com", "$argon2id$v=19$m=65536,t=1,p=2$fake", "Admin", "active", 1, now, now)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	// 2. applications
	_, err = db.ExecContext(ctx, `
		INSERT INTO applications (id, tenant_id, name, client_id, client_secret_hash, redirect_uris, scopes, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		appID, tenantID, "Web App", "web-app-client", "$argon2id$v=19$m=65536,t=1,p=2$fake",
		`["http://localhost:3000/callback"]`, `["openid","profile"]`, "active", now)
	if err != nil {
		t.Fatalf("insert application: %v", err)
	}

	// 3. credentials
	_, err = db.ExecContext(ctx, `
		INSERT INTO credentials (id, user_id, app_id, type, provider, credential_subject, secret, metadata, created_at, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		credID, userID, appID, "password", "password", "admin@example.com",
		"$argon2id$v=19$m=65536,t=1,p=2$fake", `{}`, now, now)
	if err != nil {
		t.Fatalf("insert credential: %v", err)
	}

	// 4. roles
	_, err = db.ExecContext(ctx, `
		INSERT INTO roles (id, app_id, tenant_id, name, description, is_system, version, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		roleID, appID, tenantID, "admin", "Administrator role", true, 1, now)
	if err != nil {
		t.Fatalf("insert role: %v", err)
	}

	// 5. role_permissions
	_, err = db.ExecContext(ctx, `
		INSERT INTO role_permissions (role_id, resource, action) VALUES ($1, $2, $3)`,
		roleID, "*", "*")
	if err != nil {
		t.Fatalf("insert role_permission: %v", err)
	}

	// 6. user_app_roles
	_, err = db.ExecContext(ctx, `
		INSERT INTO user_app_roles (user_id, app_id, role_id, tenant_id, assigned_at)
		VALUES ($1, $2, $3, $4, $5)`,
		userID, appID, roleID, tenantID, now)
	if err != nil {
		t.Fatalf("insert user_app_role: %v", err)
	}

	// 7. domain_events
	_, err = db.ExecContext(ctx, `
		INSERT INTO domain_events (id, aggregate_id, aggregate_type, event_type, payload, published, occurred_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		eventID, userID, "user", "user.registered", `{"email":"admin@example.com"}`, false, now)
	if err != nil {
		t.Fatalf("insert domain_event: %v", err)
	}

	// Verify row counts
	tables := map[string]int{
		"users":            1,
		"applications":     1,
		"credentials":      1,
		"roles":            1 + 3,
		"role_permissions": 1 + 5,
		"user_app_roles":   1,
		"domain_events":    1,
	}
	for table, expected := range tables {
		var count int
		err := db.QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&count)
		if err != nil {
			t.Errorf("count %s: %v", table, err)
			continue
		}
		if count != expected {
			t.Errorf("table %s: expected %d rows, got %d", table, expected, count)
		}
	}

	// Verify unique constraints work
	_, err = db.ExecContext(ctx, `
		INSERT INTO credentials (id, user_id, app_id, type, provider, credential_subject, secret, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		"c-0000000-0000-0000-0000-00000000dup", userID, appID, "password", "password", "admin@example.com",
		"$argon2id$dup", `{}`, now)
	if err == nil {
		t.Error("expected unique constraint violation on credentials (app_id, credential_subject, type), but insert succeeded")
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO users (id, tenant_id, email, password_hash, status, version, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		"u-0000000-0000-0000-0000-00000000dup", tenantID, "admin@example.com", "$argon2id$dup", "active", 1, now, now)
	if err == nil {
		t.Error("expected unique constraint violation on users (tenant_id, email), but insert succeeded")
	}
}
