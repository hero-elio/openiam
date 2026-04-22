// Command iam-bootstrap provisions the very first super_admin user
// in a fresh OpenIAM deployment.
//
// The chicken-and-egg problem: every protected REST endpoint requires
// authz checks, but a brand-new database has no users / roles to grant
// permission. This CLI bypasses the REST layer entirely and drives the
// public service interfaces directly to:
//
//  1. Create the tenant (idempotent: reuses an existing tenant by name).
//  2. Create the application (idempotent: reuses an existing app by name).
//     Application creation triggers the in-process authz event subscriber
//     which seeds the three template roles (super_admin, admin, member)
//     plus the builtin permission definitions for the app.
//  3. Register the local password user via the authn module (which
//     also creates the password credential — calling identity directly
//     would leave login failing with "credential not found").
//  4. Find the super_admin role for the app and assign it to the new user.
//  5. Print a summary table including the IDs needed to log in via /__admin.
//
// Configuration loading mirrors cmd/iam-server (config.yaml / IAM_*
// env vars), so the same secrets / DSN are reused.
//
// Usage:
//
//	go run ./cmd/iam-bootstrap \
//	    --tenant=acme \
//	    --app=portal \
//	    --email=admin@example.com \
//	    --password=<min 8 chars>
//
// The iam-server process does NOT need to be stopped while this runs:
// the outbox bus is transactional and dispatches to in-process
// subscribers within this CLI's own engine.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"

	"openiam/pkg/iam"
	"openiam/pkg/iam/authn"
	"openiam/pkg/iam/authz"
	"openiam/pkg/iam/identity"
	"openiam/pkg/iam/tenant"
)

func main() {
	tenantName := flag.String("tenant", "default", "tenant display name (created if absent)")
	appName := flag.String("app", "admin", "application display name (created if absent)")
	email := flag.String("email", "", "admin user email (required)")
	password := flag.String("password", "", "admin user password, min 8 chars (required)")
	roleName := flag.String("role", "super_admin", "role to assign to the new user")
	flag.Parse()

	if *email == "" || *password == "" {
		fmt.Fprintln(os.Stderr, "error: --email and --password are required")
		flag.Usage()
		os.Exit(2)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	cfg := loadConfig()

	engine, err := iam.New(iam.Config{
		Logger:   logger,
		Postgres: &iam.PostgresConfig{DSN: cfg.dsn},
		Redis: &iam.RedisConfig{
			Addr:     cfg.redisAddr,
			Password: cfg.redisPassword,
			DB:       cfg.redisDB,
		},
		Tenant:   &iam.TenantConfig{},
		Identity: &iam.IdentityConfig{},
		Authz:    &iam.AuthzConfig{},
		Authn: &iam.AuthnConfig{
			Config: authn.Config{
				JWTSecret:              cfg.jwtSecret,
				JWTIssuer:              cfg.jwtIssuer,
				AccessTokenTTL:         cfg.accessTTL,
				SessionTTL:             cfg.sessionTTL,
				AllowInsecureJWTSecret: cfg.allowInsecureJWT,
			},
		},
	})
	if err != nil {
		fail("initialize engine", err)
	}
	defer engine.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tenantID, tenantCreated, err := ensureTenant(ctx, engine.Tenant.Service, *tenantName)
	if err != nil {
		fail("ensure tenant", err)
	}

	appID, clientID, clientSecret, appCreated, err := ensureApplication(
		ctx, engine.Tenant.Service, tenantID, *appName,
	)
	if err != nil {
		fail("ensure application", err)
	}

	userID, userCreated, err := ensureUser(
		ctx, engine.Authn.Service, engine.Identity.Service,
		tenantID, appID, *email, *password,
	)
	if err != nil {
		fail("ensure user", err)
	}

	roleID, alreadyAssigned, err := ensureRoleAssignment(
		ctx, engine.Authz.Service, appID, tenantID, userID, *roleName,
	)
	if err != nil {
		fail("assign role", err)
	}

	printSummary(summary{
		tenantID:        tenantID,
		tenantName:      *tenantName,
		tenantCreated:   tenantCreated,
		appID:           appID,
		appName:         *appName,
		appCreated:      appCreated,
		clientID:        clientID,
		clientSecret:    clientSecret,
		userID:          userID,
		userCreated:     userCreated,
		email:           *email,
		password:        *password,
		roleID:          roleID,
		roleName:        *roleName,
		alreadyAssigned: alreadyAssigned,
	})
}

type config struct {
	dsn              string
	redisAddr        string
	redisPassword    string
	redisDB          int
	jwtSecret        string
	jwtIssuer        string
	accessTTL        time.Duration
	sessionTTL       time.Duration
	allowInsecureJWT bool
}

func loadConfig() config {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("./config")
	v.AddConfigPath(".")
	v.SetEnvPrefix("IAM")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	v.SetTypeByDefaultValue(true)

	v.SetDefault("database.dsn", "postgres://postgres:postgres@localhost:5432/iam?sslmode=disable")
	v.SetDefault("redis.addr", "localhost:6379")
	v.SetDefault("redis.password", "")
	v.SetDefault("redis.db", 0)
	v.SetDefault("jwt.secret", authn.InsecureJWTSecretSentinel)
	v.SetDefault("jwt.allow_insecure", false)
	v.SetDefault("jwt.issuer", "openiam")
	v.SetDefault("jwt.access_ttl", "15m")
	v.SetDefault("session.ttl", "168h")

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			fail("read config", err)
		}
	}

	accessTTL, err := time.ParseDuration(v.GetString("jwt.access_ttl"))
	if err != nil {
		fail("parse jwt.access_ttl", err)
	}
	sessionTTL, err := time.ParseDuration(v.GetString("session.ttl"))
	if err != nil {
		fail("parse session.ttl", err)
	}

	return config{
		dsn:              v.GetString("database.dsn"),
		redisAddr:        v.GetString("redis.addr"),
		redisPassword:    v.GetString("redis.password"),
		redisDB:          v.GetInt("redis.db"),
		jwtSecret:        v.GetString("jwt.secret"),
		jwtIssuer:        v.GetString("jwt.issuer"),
		accessTTL:        accessTTL,
		sessionTTL:       sessionTTL,
		allowInsecureJWT: v.GetBool("jwt.allow_insecure"),
	}
}

func ensureTenant(ctx context.Context, svc tenant.Service, name string) (string, bool, error) {
	existing, err := svc.ListTenants(ctx, &tenant.ListTenantsQuery{Limit: 0, Offset: 0})
	if err != nil {
		return "", false, err
	}
	for _, t := range existing {
		if strings.EqualFold(t.Name, name) {
			return t.ID, false, nil
		}
	}
	id, err := svc.CreateTenant(ctx, &tenant.CreateTenantCommand{Name: name})
	if err != nil {
		return "", false, err
	}
	return id.String(), true, nil
}

func ensureApplication(ctx context.Context, svc tenant.Service, tenantID, name string) (
	appID, clientID, clientSecret string, created bool, err error,
) {
	apps, err := svc.ListApplications(ctx, &tenant.ListApplicationsQuery{TenantID: tenantID})
	if err != nil {
		return "", "", "", false, err
	}
	for _, a := range apps {
		if strings.EqualFold(a.Name, name) {
			return a.ID, a.ClientID, "", false, nil
		}
	}
	res, err := svc.CreateApplication(ctx, &tenant.CreateApplicationCommand{
		TenantID:  tenantID,
		Name:      name,
		CreatedBy: "", // empty => seed roles + permission defs but skip auto-assignment
	})
	if err != nil {
		return "", "", "", false, err
	}
	return res.Application.ID, res.Application.ClientID, res.ClientSecret, true, nil
}

// ensureUser registers the admin user via the authn module so that
// BOTH the user record AND the password credential are created
// atomically. Calling identity.RegisterUser directly would only
// create the user row and leave a /auth/login attempt failing with
// "credential not found".
func ensureUser(ctx context.Context, authnSvc authn.Service, identitySvc identity.Service,
	tenantID, appID, email, password string,
) (string, bool, error) {
	if existing, err := identitySvc.FindByEmail(ctx, identity.TenantID(tenantID), email); err == nil && existing != nil {
		return existing.ID, false, nil
	}
	if _, err := authnSvc.Register(ctx, &authn.RegisterCommand{
		AppID:    appID,
		TenantID: tenantID,
		Email:    email,
		Password: password,
		Provider: "password",
	}); err != nil {
		return "", false, err
	}
	dto, err := identitySvc.FindByEmail(ctx, identity.TenantID(tenantID), email)
	if err != nil {
		return "", false, fmt.Errorf("lookup newly registered user: %w", err)
	}
	return dto.ID, true, nil
}

func ensureRoleAssignment(ctx context.Context, svc authz.Service,
	appID, tenantID, userID, roleName string,
) (string, bool, error) {
	roles, err := svc.ListRoles(ctx, &authz.ListRolesQuery{AppID: appID})
	if err != nil {
		return "", false, err
	}

	var roleID string
	for _, r := range roles {
		if r.Name == roleName {
			roleID = r.ID
			break
		}
	}
	if roleID == "" {
		return "", false, fmt.Errorf("role %q not found in app %s (got %d roles)", roleName, appID, len(roles))
	}

	existing, err := svc.ListUserRoles(ctx, &authz.ListUserRolesQuery{UserID: userID, AppID: appID})
	if err != nil {
		return "", false, err
	}
	for _, ur := range existing {
		if ur.RoleID == roleID {
			return roleID, true, nil
		}
	}

	if err := svc.AssignRole(ctx, &authz.AssignRoleCommand{
		UserID:   userID,
		AppID:    appID,
		RoleID:   roleID,
		TenantID: tenantID,
	}); err != nil {
		return "", false, err
	}
	return roleID, false, nil
}

type summary struct {
	tenantID, tenantName string
	tenantCreated        bool
	appID, appName       string
	appCreated           bool
	clientID             string
	clientSecret         string
	userID               string
	userCreated          bool
	email, password      string
	roleID, roleName     string
	alreadyAssigned      bool
}

func printSummary(s summary) {
	mark := func(created bool) string {
		if created {
			return "CREATED"
		}
		return "EXISTS "
	}

	fmt.Println()
	fmt.Println("OpenIAM bootstrap completed.")
	fmt.Println("================================================================")
	fmt.Printf("  Tenant   [%s]   id=%s   name=%s\n", mark(s.tenantCreated), s.tenantID, s.tenantName)
	fmt.Printf("  App      [%s]   id=%s   name=%s\n", mark(s.appCreated), s.appID, s.appName)
	fmt.Printf("                       client_id=%s\n", s.clientID)
	if s.clientSecret != "" {
		fmt.Printf("                       client_secret=%s   (one-time display)\n", s.clientSecret)
	}
	fmt.Printf("  User     [%s]   id=%s   email=%s\n", mark(s.userCreated), s.userID, s.email)
	if s.alreadyAssigned {
		fmt.Printf("  Role     [EXISTS ]   id=%s   name=%s   (assignment already present)\n", s.roleID, s.roleName)
	} else {
		fmt.Printf("  Role     [ASSIGNED]  id=%s   name=%s\n", s.roleID, s.roleName)
	}
	fmt.Println("================================================================")
	fmt.Println()
	fmt.Println("Log in to the admin UI:")
	fmt.Println("  URL:       http://localhost:8080/__admin")
	fmt.Printf("  tenant_id: %s\n", s.tenantID)
	fmt.Printf("  app_id:    %s\n", s.appID)
	fmt.Printf("  email:     %s\n", s.email)
	fmt.Printf("  password:  %s\n", s.password)
	fmt.Println()
}

func fail(stage string, err error) {
	fmt.Fprintf(os.Stderr, "iam-bootstrap: %s: %v\n", stage, err)
	os.Exit(1)
}
