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
	"github.com/redis/go-redis/v9"

	"openiam/internal/authn"
	authnPersistence "openiam/internal/authn/adapter/outbound/persistence"
	authnRateLimit "openiam/internal/authn/adapter/outbound/ratelimit"
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
		e.lateBindAuthzExistence()
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
			Apps:          e.scopeValidatorOrNil(),
			TokenProvider: jwtProvider,
			RateLimiter:   authnRateLimit.NewRedis(e.Deps.Redis),
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
		e.lateBindAuthzExistence()
		return nil
	}
}

func WithTenant() Option {
	return func(e *Engine) error {
		e.ensureDefaults()
		e.Tenant = tenant.NewManager(e.Deps.DB, e.Deps.EventBus, e.Deps.TxManager, e.checkerOrNil())
		e.lateBindScopeValidator()
		e.lateBindAuthzExistence()
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

	// Liveness: cheap, no external deps. Returning 200 means the process
	// is up and the HTTP stack is serving — that's all Kubernetes needs to
	// stop killing the pod.
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeHealthJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})

	// Readiness: verify the dependencies a request actually needs. Both
	// Postgres and Redis are pinged with the request's context so a slow
	// dep can't pin the probe to its server-wide timeout.
	r.Get("/readyz", e.handleReadyz)

	r.Route("/api/v1", func(api chi.Router) {
		// Cap request bodies before any handler reads them, so a
		// streaming attack can't OOM us by feeding json.Decode a
		// gigabyte payload. The cap applies to every API route
		// (auth + protected) — health endpoints stay unrestricted.
		api.Use(mw.BodyLimit(mw.DefaultMaxRequestBodyBytes))

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

func (e *Engine) handleReadyz(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{}
	overall := http.StatusOK

	if e.Deps.DB != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		if err := e.Deps.DB.PingContext(ctx); err != nil {
			checks["postgres"] = "unhealthy: " + err.Error()
			overall = http.StatusServiceUnavailable
		} else {
			checks["postgres"] = "ok"
		}
		cancel()
	}

	if e.Deps.Redis != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		if err := e.Deps.Redis.Ping(ctx).Err(); err != nil {
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
		// When a database is configured, default to the transactional
		// outbox bus: every event is durably recorded in domain_events
		// inside the caller's tx, then dispatched in-process. Without
		// a DB (tests, embedded use) we fall back to the in-memory bus
		// so callers don't need to wire anything extra.
		if e.Deps.DB != nil {
			e.Deps.EventBus = eventbus.NewOutboxEventBus(e.Deps.DB, e.Deps.Logger)
		} else {
			e.Deps.EventBus = eventbus.NewMemoryEventBus(e.Deps.Logger)
		}
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

// lateBindAuthzExistence wires the subject-existence port into the
// authz service once both identity and tenant modules are available.
// Called from WithIdentity, WithTenant, and WithAuthz so the order of
// option application doesn't matter.
func (e *Engine) lateBindAuthzExistence() {
	if e.Authz == nil || e.Identity == nil || e.Tenant == nil {
		return
	}
	e.Authz.Service.SetSubjectExistence(subjectExistenceAdapter{
		identity: e.Identity,
		tenant:   e.Tenant,
	})
}

// subjectExistenceAdapter composes Identity and Tenant into the single
// authz domain port. Lives here (in the wiring layer) so neither
// upstream module needs to know about the authz interface.
type subjectExistenceAdapter struct {
	identity *identity.Registry
	tenant   *tenant.Manager
}

func (a subjectExistenceAdapter) UserExists(ctx context.Context, id shared.UserID) (bool, error) {
	return a.identity.Service.UserExists(ctx, id)
}

func (a subjectExistenceAdapter) AppExists(ctx context.Context, id shared.AppID) (bool, error) {
	return a.tenant.Service.AppExists(ctx, id)
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
