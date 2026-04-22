package iam

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/jmoiron/sqlx"
	"github.com/redis/go-redis/v9"

	"openiam/internal/authn"
	authnPersistence "openiam/internal/authn/adapter/outbound/persistence"
	authnToken "openiam/internal/authn/adapter/outbound/token"
	"openiam/internal/authz"
	"openiam/internal/identity"
	"openiam/internal/tenant"

	shared "openiam/internal/shared/domain"
	"openiam/internal/shared/infra/eventbus"
	"openiam/internal/shared/infra/persistence"

	mw "openiam/pkg/middleware"
)

// Deps holds shared infrastructure that modules depend on.
type Deps struct {
	DB        *sqlx.DB
	Redis     *redis.Client
	EventBus  shared.EventBus
	TxManager *persistence.TxManager
	Logger    *slog.Logger
}

// Engine holds initialized modules and the assembled HTTP router.
type Engine struct {
	Identity *identity.Registry
	Authn    *authn.Authenticator
	Authz    *authz.Authorizer
	Tenant   *tenant.Manager
	Deps     Deps

	router    chi.Router
	closers   []func() error
}

type Option func(e *Engine) error

// --- Infrastructure options ---

func WithPostgres(dsn string) Option {
	return func(e *Engine) error {
		db, err := sqlx.Connect("postgres", dsn)
		if err != nil {
			return fmt.Errorf("connect postgres: %w", err)
		}
		e.Deps.DB = db
		e.Deps.TxManager = persistence.NewTxManager(db)
		e.closers = append(e.closers, db.Close)
		return nil
	}
}

func WithDB(db *sqlx.DB) Option {
	return func(e *Engine) error {
		e.Deps.DB = db
		e.Deps.TxManager = persistence.NewTxManager(db)
		return nil
	}
}

func WithRedis(addr, password string, db int) Option {
	return func(e *Engine) error {
		rdb := redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: password,
			DB:       db,
		})
		if err := rdb.Ping(context.Background()).Err(); err != nil {
			return fmt.Errorf("connect redis: %w", err)
		}
		e.Deps.Redis = rdb
		e.closers = append(e.closers, rdb.Close)
		return nil
	}
}

func WithRedisClient(rdb *redis.Client) Option {
	return func(e *Engine) error {
		e.Deps.Redis = rdb
		return nil
	}
}

func WithEventBus(bus shared.EventBus) Option {
	return func(e *Engine) error {
		e.Deps.EventBus = bus
		return nil
	}
}

func WithLogger(logger *slog.Logger) Option {
	return func(e *Engine) error {
		e.Deps.Logger = logger
		return nil
	}
}

// --- Module options ---

func WithIdentity() Option {
	return func(e *Engine) error {
		e.ensureDefaults()
		e.Identity = identity.NewRegistry(
			e.Deps.DB,
			e.Deps.EventBus,
			e.Deps.TxManager,
			e.checkerOrNil(),
			e.scopeValidatorOrNil(),
		)
		return nil
	}
}

func WithAuthn(cfg authn.Config) Option {
	return func(e *Engine) error {
		e.ensureDefaults()
		if e.Identity == nil {
			return fmt.Errorf("WithAuthn requires WithIdentity to be applied first")
		}
		if e.Deps.Redis == nil {
			return fmt.Errorf("WithAuthn requires Redis (use WithRedis)")
		}
		jwtProvider := authnToken.NewJWTProvider(authnToken.JWTConfig{
			Secret:         cfg.JWTSecret,
			Issuer:         cfg.JWTIssuer,
			AccessTokenTTL: cfg.AccessTokenTTL,
		})
		mod, err := authn.NewAuthenticator(cfg, authn.AuthenticatorDeps{
			Credentials:   authnPersistence.NewPostgresCredentialRepo(e.Deps.DB),
			Sessions:      authnPersistence.NewRedisSessionRepo(e.Deps.Redis),
			Challenges:    authnPersistence.NewRedisChallengeStore(e.Deps.Redis),
			EventBus:      e.Deps.EventBus,
			Identity:      authn.NewIdentityBridge(e.Identity.Service),
			TokenProvider: jwtProvider,
			Logger:        e.Deps.Logger,
		})
		if err != nil {
			return err
		}
		e.Authn = mod
		return nil
	}
}

func WithAuthz() Option {
	return func(e *Engine) error {
		e.ensureDefaults()
		mod, err := authz.NewAuthorizer(e.Deps.DB, e.Deps.EventBus, e.Deps.TxManager)
		if err != nil {
			return err
		}
		e.Authz = mod
		e.lateBindChecker()
		return nil
	}
}

func WithTenant() Option {
	return func(e *Engine) error {
		e.ensureDefaults()
		e.Tenant = tenant.NewManager(e.Deps.DB, e.Deps.EventBus, e.Deps.TxManager, e.checkerOrNil())
		e.lateBindScopeValidator()
		return nil
	}
}

// New creates an Engine by applying the given options in order.
// Infrastructure options (WithPostgres, WithRedis) must come before module
// options (WithIdentity, WithAuthn, WithAuthz, WithTenant).
func New(opts ...Option) (*Engine, error) {
	e := &Engine{}

	for _, opt := range opts {
		if err := opt(e); err != nil {
			e.Close()
			return nil, err
		}
	}

	return e, nil
}

// Handler returns an http.Handler with all registered module routes mounted
// at their default paths under /api/v1.
func (e *Engine) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(30 * time.Second))

	r.Route("/api/v1", func(api chi.Router) {
		if e.Authn != nil && e.Authn.Handler != nil {
			api.Mount("/auth", e.Authn.Handler.Routes())
			r.Mount("/__test/authn", http.StripPrefix("/__test/authn", testAuthnPageHandler()))
		}

		api.Group(func(protected chi.Router) {
			if e.Authn != nil {
				protected.Use(mw.BearerAuth(e.Authn.TokenProvider))
			}

			if e.Tenant != nil && e.Tenant.Handler != nil {
				protected.Mount("/tenants", e.Tenant.Handler.TenantRoutes())
				protected.Mount("/applications", e.Tenant.Handler.ApplicationRoutes())
			}
			if e.Identity != nil && e.Identity.Handler != nil {
				protected.Mount("/users", e.Identity.Handler.Routes())
			}
			if e.Authz != nil && e.Authz.Handler != nil {
				protected.Mount("/authz", e.Authz.Handler.Routes())
			}
		})
	})

	e.router = r
	return r
}

func (e *Engine) Close() error {
	var first error
	for i := len(e.closers) - 1; i >= 0; i-- {
		if err := e.closers[i](); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (e *Engine) checkerOrNil() func(ctx context.Context, resource, action string) error {
	if e.Authz != nil {
		return e.Authz.Checker
	}
	return nil
}

func (e *Engine) scopeValidatorOrNil() *tenant.ScopeAdapter {
	if e.Tenant == nil {
		return nil
	}
	return tenant.NewScopeAdapter(e.Tenant)
}

func (e *Engine) ensureDefaults() {
	if e.Deps.Logger == nil {
		e.Deps.Logger = slog.Default()
	}
	if e.Deps.EventBus == nil {
		e.Deps.EventBus = eventbus.NewMemoryEventBus(e.Deps.Logger)
	}
}

// lateBindChecker re-creates handlers for modules that were initialized before
// the authz Checker was available.
func (e *Engine) lateBindChecker() {
	if e.Authz == nil {
		return
	}
	check := e.Authz.Checker

	if e.Identity != nil && e.Identity.Handler == nil {
		e.Identity = identity.NewRegistry(e.Deps.DB, e.Deps.EventBus, e.Deps.TxManager, check, e.scopeValidatorOrNil())
	}
	if e.Tenant != nil && e.Tenant.Handler == nil {
		e.Tenant = tenant.NewManager(e.Deps.DB, e.Deps.EventBus, e.Deps.TxManager, check)
	}
}

// lateBindScopeValidator rewires Identity to pick up the tenant scope
// validator when WithTenant is applied after WithIdentity.
func (e *Engine) lateBindScopeValidator() {
	if e.Tenant == nil || e.Identity == nil {
		return
	}
	e.Identity = identity.NewRegistry(
		e.Deps.DB,
		e.Deps.EventBus,
		e.Deps.TxManager,
		e.checkerOrNil(),
		e.scopeValidatorOrNil(),
	)
}
