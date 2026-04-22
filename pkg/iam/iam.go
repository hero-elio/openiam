// Package iam is the convenience entry point for the OpenIAM SDK.
//
// Three usage styles are supported and tested:
//
//  1. "Batteries included" — pass a single Config to New, get back an
//     Engine with every configured module wired up and an http.Handler
//     ready to serve. This is what most embedders want.
//
//  2. "Compose your own" — depend on the per-module sub-packages
//     (pkg/iam/authn, pkg/iam/identity, pkg/iam/authz, pkg/iam/tenant)
//     directly and assemble them with the adapters that suit your
//     deployment (pkg/iam/adapters/{postgres,redis,jwt,memory}).
//     Useful when only a subset of modules is needed, or when the
//     transport stack is not stock REST.
//
//  3. "Bring your own storage" — implement the public port interfaces
//     (e.g. authn.CredentialStore, identity.UserStore) against your
//     own backend, then wire them into either of the above. The
//     in-memory adapter package doubles as a reference implementation.
//
// See the package examples and pkg/iam/adapters/memory/smoke_test.go
// for runnable end-to-end snippets.
package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/jmoiron/sqlx"
	goredis "github.com/redis/go-redis/v9"

	sharedDomain "openiam/internal/shared/domain"
	sharedPersistence "openiam/internal/shared/infra/persistence"

	"openiam/pkg/iam/adapters/jwt"
	"openiam/pkg/iam/adapters/postgres"
	redisAdapters "openiam/pkg/iam/adapters/redis"
	"openiam/pkg/iam/authn"
	"openiam/pkg/iam/authz"
	"openiam/pkg/iam/eventbus"
	"openiam/pkg/iam/identity"
	"openiam/pkg/iam/internal/adminpage"
	"openiam/pkg/iam/internal/testpage"
	"openiam/pkg/iam/tenant"
	transportRest "openiam/pkg/iam/transport/rest"
)

// PostgresConfig describes how to obtain a *sqlx.DB. Provide DB to
// reuse a connection pool the host already manages, or DSN to let the
// Builder open a fresh connection (closed by Engine.Close).
type PostgresConfig struct {
	DSN string
	DB  *sqlx.DB
}

// RedisConfig describes how to obtain a *redis.Client. Provide Client
// to reuse one the host already manages, or Addr/Password/DB to let
// the Builder dial a fresh connection (closed by Engine.Close).
type RedisConfig struct {
	Addr     string
	Password string
	DB       int
	Client   *goredis.Client
}

// JWTConfig is the local copy of jwt.Config carried by AuthnConfig so
// SDK consumers can configure the bundled token provider without
// importing the adapter package directly.
type JWTConfig = jwt.Config

// AuthnConfig configures the authn module. The embedded authn.Config
// covers the protocol-level tunables; the optional override fields
// let SDK consumers swap in custom adapter implementations (e.g. a
// Postgres-backed session store for audit reasons).
//
// When an override field is nil the Builder picks a sensible default
// from the configured Postgres / Redis connection.
type AuthnConfig struct {
	authn.Config

	// JWT is the configuration for the bundled HMAC-JWT token
	// provider. Ignored when TokenProvider is set.
	JWT JWTConfig

	// Optional adapter overrides.
	Credentials   authn.CredentialStore
	Sessions      authn.SessionStore
	Challenges    authn.ChallengeStore
	TokenProvider authn.TokenProvider
	RateLimiter   authn.RateLimiter

	// AppDirectory overrides the default tenant-derived
	// AppDirectory. Useful when SIWE / WebAuthn are enabled but
	// the host does not want to install the full tenant module.
	AppDirectory authn.AppDirectory
}

// IdentityConfig configures the identity module.
type IdentityConfig struct {
	identity.Config

	// Users overrides the default Postgres user store.
	Users identity.UserStore

	// Scopes overrides the default tenant-derived ScopeValidator.
	// Ignored when the tenant module is also configured (the
	// tenant bridge wins).
	Scopes identity.ScopeValidator
}

// AuthzConfig configures the authz module.
type AuthzConfig struct {
	authz.Config

	// Optional adapter overrides for the authz stores.
	Roles                 authz.RoleStore
	ResourcePermissions   authz.ResourcePermissionStore
	PermissionDefinitions authz.PermissionDefinitionStore

	// SubjectExistence overrides the composed identity+tenant port.
	// Pass authz.NoOpSubjectExistence to opt out of the pre-check
	// in standalone deployments.
	SubjectExistence authz.SubjectExistence
}

// TenantConfig configures the tenant module.
type TenantConfig struct {
	tenant.Config

	// Optional adapter overrides for the tenant stores.
	Tenants      tenant.TenantStore
	Applications tenant.ApplicationStore
}

// Config is the single argument to New. Each module pointer is
// optional: leaving it nil disables that module entirely.
//
// The Builder enforces the cross-module dependency rules at boot
// (e.g. authn requires identity, both require an event bus and a
// transaction manager) and returns a typed error before any HTTP
// listener is opened.
type Config struct {
	// Logger is the slog logger every module receives. Defaults to
	// slog.Default().
	Logger *slog.Logger

	// Postgres / Redis describe the optional shared infrastructure.
	// Modules that need persistence look here first; if a module
	// defines its own override (e.g. AuthnConfig.Credentials) that
	// override wins.
	Postgres *PostgresConfig
	Redis    *RedisConfig

	// EventBus overrides the auto-picked bus. When nil the Builder
	// uses the transactional outbox bus when Postgres is
	// configured, falling back to the in-memory bus otherwise.
	EventBus eventbus.Bus

	// Module configurations. Setting a field non-nil enables the
	// corresponding module.
	Authn    *AuthnConfig
	Identity *IdentityConfig
	Authz    *AuthzConfig
	Tenant   *TenantConfig
}

// Engine is the assembled IAM stack. Module fields are nil when their
// corresponding Config section was omitted; transports check for nil
// before mounting routes.
type Engine struct {
	Logger *slog.Logger

	DB    *sqlx.DB
	Redis *goredis.Client
	Bus   eventbus.Bus

	Authn    *authn.Module
	Identity *identity.Module
	Authz    *authz.Module
	Tenant   *tenant.Module

	closers []func() error
}

// New builds an Engine from cfg. Returns the first error encountered
// during dependency resolution; partially constructed resources
// (database connections, redis clients) are closed before returning.
func New(cfg Config) (*Engine, error) {
	e := &Engine{Logger: cfg.Logger}
	if e.Logger == nil {
		e.Logger = slog.Default()
	}

	if err := e.openInfra(cfg); err != nil {
		_ = e.Close()
		return nil, err
	}

	pgAdapters, hasPg := e.postgresAdapters()

	bus, err := e.resolveEventBus(cfg)
	if err != nil {
		_ = e.Close()
		return nil, err
	}
	e.Bus = bus

	txMgr := e.txManager()

	if cfg.Tenant != nil {
		mod, err := buildTenant(cfg.Tenant, pgAdapters, hasPg, bus, txMgr)
		if err != nil {
			_ = e.Close()
			return nil, fmt.Errorf("tenant: %w", err)
		}
		e.Tenant = mod
	}

	if cfg.Identity != nil {
		mod, err := buildIdentity(cfg.Identity, pgAdapters, hasPg, bus, txMgr, e.Tenant)
		if err != nil {
			_ = e.Close()
			return nil, fmt.Errorf("identity: %w", err)
		}
		e.Identity = mod
	}

	if cfg.Authz != nil {
		mod, err := buildAuthz(cfg.Authz, pgAdapters, hasPg, bus, txMgr, e.Identity, e.Tenant)
		if err != nil {
			_ = e.Close()
			return nil, fmt.Errorf("authz: %w", err)
		}
		e.Authz = mod
	}

	if cfg.Authn != nil {
		mod, err := buildAuthn(cfg.Authn, pgAdapters, hasPg, e.Redis, bus, e.Logger, e.Identity, e.Tenant)
		if err != nil {
			_ = e.Close()
			return nil, fmt.Errorf("authn: %w", err)
		}
		e.Authn = mod
	}

	return e, nil
}

func (e *Engine) openInfra(cfg Config) error {
	if cfg.Postgres != nil {
		switch {
		case cfg.Postgres.DB != nil:
			e.DB = cfg.Postgres.DB
		case cfg.Postgres.DSN != "":
			db, err := sqlx.Connect("postgres", cfg.Postgres.DSN)
			if err != nil {
				return fmt.Errorf("connect postgres: %w", err)
			}
			e.DB = db
			e.closers = append(e.closers, db.Close)
		}
	}

	if cfg.Redis != nil {
		switch {
		case cfg.Redis.Client != nil:
			e.Redis = cfg.Redis.Client
		case cfg.Redis.Addr != "":
			rdb := goredis.NewClient(&goredis.Options{
				Addr:     cfg.Redis.Addr,
				Password: cfg.Redis.Password,
				DB:       cfg.Redis.DB,
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := rdb.Ping(ctx).Err(); err != nil {
				_ = rdb.Close()
				return fmt.Errorf("connect redis: %w", err)
			}
			e.Redis = rdb
			e.closers = append(e.closers, rdb.Close)
		}
	}

	return nil
}

func (e *Engine) postgresAdapters() (postgres.AdapterSet, bool) {
	if e.DB == nil {
		return postgres.AdapterSet{}, false
	}
	return postgres.Adapters(e.DB), true
}

func (e *Engine) txManager() sharedDomain.TxManager {
	if e.DB == nil {
		// No persistence => no real transactions; identity / authz
		// still ask for one, so we hand them a no-op that just
		// runs the closure inline. Same shape as the memory
		// adapter's TxManager.
		return noopTxManager{}
	}
	return sharedPersistence.NewTxManager(e.DB)
}

func (e *Engine) resolveEventBus(cfg Config) (eventbus.Bus, error) {
	if cfg.EventBus != nil {
		return cfg.EventBus, nil
	}
	if e.DB != nil {
		return eventbus.NewOutbox(e.DB, e.Logger), nil
	}
	return eventbus.NewMemory(e.Logger), nil
}

// noopTxManager runs every closure inline. Useful for the in-memory
// path where no real transactions are available; mirrors the shape of
// pkg/iam/adapters/memory.TxManager so wiring stays uniform.
type noopTxManager struct{}

func (noopTxManager) Execute(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

var _ sharedDomain.TxManager = noopTxManager{}

func buildTenant(cfg *TenantConfig, pg postgres.AdapterSet, hasPg bool, bus eventbus.Bus, txMgr sharedDomain.TxManager) (*tenant.Module, error) {
	deps := tenant.Deps{
		Tenants:      cfg.Tenants,
		Applications: cfg.Applications,
		EventBus:     bus,
		TxManager:    txMgr,
	}
	if deps.Tenants == nil && hasPg {
		deps.Tenants = pg.Tenants
	}
	if deps.Applications == nil && hasPg {
		deps.Applications = pg.Applications
	}
	return tenant.New(cfg.Config, deps)
}

func buildIdentity(cfg *IdentityConfig, pg postgres.AdapterSet, hasPg bool, bus eventbus.Bus, txMgr sharedDomain.TxManager, tenantMod *tenant.Module) (*identity.Module, error) {
	deps := identity.Deps{
		Users:     cfg.Users,
		EventBus:  bus,
		TxManager: txMgr,
		Scopes:    cfg.Scopes,
	}
	if deps.Users == nil && hasPg {
		deps.Users = pg.Users
	}
	// tenant-derived scope validator wins over the manual override:
	// the tenant module is the source of truth for what tenants /
	// apps exist. Callers can still pass identity.Scopes when they
	// intentionally run identity without tenant.
	if tenantMod != nil {
		deps.Scopes = tenant.ScopeValidatorFor(tenantMod.Service)
	}
	return identity.New(cfg.Config, deps)
}

func buildAuthz(cfg *AuthzConfig, pg postgres.AdapterSet, hasPg bool, bus eventbus.Bus, txMgr sharedDomain.TxManager, identityMod *identity.Module, tenantMod *tenant.Module) (*authz.Module, error) {
	deps := authz.Deps{
		Roles:                 cfg.Roles,
		ResourcePermissions:   cfg.ResourcePermissions,
		PermissionDefinitions: cfg.PermissionDefinitions,
		EventBus:              bus,
		TxManager:             txMgr,
		SubjectExistence:      cfg.SubjectExistence,
	}
	if deps.Roles == nil && hasPg {
		deps.Roles = pg.Roles
	}
	if deps.ResourcePermissions == nil && hasPg {
		deps.ResourcePermissions = pg.ResourcePermissions
	}
	if deps.PermissionDefinitions == nil && hasPg {
		deps.PermissionDefinitions = pg.PermissionDefinitions
	}
	if deps.SubjectExistence == nil {
		var users authz.UserExistence
		var apps authz.AppExistence
		if identityMod != nil {
			users = identity.SubjectExistenceFor(identityMod.Service)
		}
		if tenantMod != nil {
			apps = tenant.SubjectExistenceFor(tenantMod.Service)
		}
		if users != nil || apps != nil {
			deps.SubjectExistence = authz.ComposeSubjectExistence(users, apps)
		} else {
			// No identity / tenant => compose would refuse every
			// grant. Fall back to the explicit no-op so the
			// authz module is usable on its own.
			deps.SubjectExistence = authz.NoOpSubjectExistence{}
		}
	}
	return authz.New(cfg.Config, deps)
}

func buildAuthn(cfg *AuthnConfig, pg postgres.AdapterSet, hasPg bool, rdb *goredis.Client, bus eventbus.Bus, logger *slog.Logger, identityMod *identity.Module, tenantMod *tenant.Module) (*authn.Module, error) {
	if identityMod == nil {
		return nil, fmt.Errorf("authn requires Config.Identity to be configured")
	}

	deps := authn.Deps{
		Credentials:   cfg.Credentials,
		Sessions:      cfg.Sessions,
		Challenges:    cfg.Challenges,
		EventBus:      bus,
		Identity:      identity.IntegrationFor(identityMod.Service),
		TokenProvider: cfg.TokenProvider,
		AppDirectory:  cfg.AppDirectory,
		RateLimiter:   cfg.RateLimiter,
		Logger:        logger,
	}

	if deps.Credentials == nil && hasPg {
		deps.Credentials = pg.Credentials
	}

	if rdb != nil {
		redisSet := redisAdapters.AuthnAdapters(rdb)
		if deps.Sessions == nil {
			deps.Sessions = redisSet.Sessions
		}
		if deps.Challenges == nil {
			deps.Challenges = redisSet.Challenges
		}
		if deps.RateLimiter == nil {
			deps.RateLimiter = redisSet.RateLimiter
		}
	}

	if deps.AppDirectory == nil && tenantMod != nil {
		deps.AppDirectory = tenant.AppDirectoryFor(tenantMod.Service)
	}

	if deps.TokenProvider == nil {
		// Derive a JWT provider from the embedded JWTConfig, falling
		// back to the authn Config's secret/issuer/TTL when JWTConfig
		// is left zero.
		jc := cfg.JWT
		if jc.Secret == "" {
			jc.Secret = cfg.Config.JWTSecret
		}
		if jc.Issuer == "" {
			jc.Issuer = cfg.Config.JWTIssuer
		}
		if jc.AccessTokenTTL == 0 {
			jc.AccessTokenTTL = cfg.Config.AccessTokenTTL
		}
		deps.TokenProvider = jwt.TokenProvider(jc)
	}

	return authn.New(cfg.Config, deps)
}

// Handler returns an http.Handler with all configured module routes
// mounted at their default paths under /api/v1, plus liveness and
// readiness probes at /healthz and /readyz.
//
// Mounting goes through pkg/iam/transport/rest so the same Mount*
// helpers power both this convenience entry point and any custom
// router an SDK consumer assembles.
func (e *Engine) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(30 * time.Second))

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeHealthJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	r.Get("/readyz", e.handleReadyz)

	r.Route("/api/v1", func(api chi.Router) {
		api.Use(transportRest.BodyLimit(transportRest.DefaultMaxRequestBodyBytes))

		if e.Authn != nil {
			api.Route("/auth", func(auth chi.Router) {
				transportRest.MountAuthn(auth, e.Authn.Service)
			})
			r.Mount("/__test/authn", http.StripPrefix("/__test/authn", testpage.Handler()))
			r.Mount("/__admin", http.StripPrefix("/__admin", adminpage.Handler()))
		}

		api.Group(func(protected chi.Router) {
			if e.Authn != nil {
				protected.Use(transportRest.BearerAuth(e.Authn.Service.AuthenticateToken))
			}

			var check func(ctx context.Context, resource, action string) error
			if e.Authz != nil {
				check = e.Authz.Checker
			}

			if e.Tenant != nil && check != nil {
				protected.Route("/tenants", func(t chi.Router) {
					transportRest.MountTenant(t, e.Tenant.Service, check)
				})
				protected.Route("/applications", func(a chi.Router) {
					transportRest.MountApplications(a, e.Tenant.Service, check)
				})
			}
			if e.Identity != nil && check != nil {
				protected.Route("/users", func(u chi.Router) {
					transportRest.MountIdentity(u, e.Identity.Service, check)
				})
			}
			if e.Authz != nil && check != nil {
				protected.Route("/authz", func(a chi.Router) {
					transportRest.MountAuthz(a, e.Authz.Service, check)
				})
			}
		})
	})

	return r
}

func (e *Engine) handleReadyz(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{}
	overall := http.StatusOK

	if e.DB != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		if err := e.DB.PingContext(ctx); err != nil {
			checks["postgres"] = "unhealthy: " + err.Error()
			overall = http.StatusServiceUnavailable
		} else {
			checks["postgres"] = "ok"
		}
		cancel()
	}

	if e.Redis != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		if err := e.Redis.Ping(ctx).Err(); err != nil {
			checks["redis"] = "unhealthy: " + err.Error()
			overall = http.StatusServiceUnavailable
		} else {
			checks["redis"] = "ok"
		}
		cancel()
	}

	body := map[string]any{
		"status": "ok",
		"checks": checks,
	}
	if overall != http.StatusOK {
		body["status"] = "degraded"
	}
	writeHealthJSON(w, overall, body)
}

func writeHealthJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// Close releases every resource the Builder opened (database, redis).
// Resources passed in via PostgresConfig.DB or RedisConfig.Client are
// owned by the caller and left untouched.
func (e *Engine) Close() error {
	var first error
	for i := len(e.closers) - 1; i >= 0; i-- {
		if err := e.closers[i](); err != nil && first == nil {
			first = err
		}
	}
	return first
}
