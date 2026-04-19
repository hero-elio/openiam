package iam

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jmoiron/sqlx"
	"github.com/redis/go-redis/v9"

	authnEvent "openiam/internal/authn/adapter/inbound/event"
	authnRest "openiam/internal/authn/adapter/inbound/rest"
	authnPersistence "openiam/internal/authn/adapter/outbound/persistence"
	authnStrategy "openiam/internal/authn/adapter/outbound/strategy"
	authnToken "openiam/internal/authn/adapter/outbound/token"
	authnApp "openiam/internal/authn/application"

	authzEvent "openiam/internal/authz/adapter/inbound/event"
	authzRest "openiam/internal/authz/adapter/inbound/rest"
	authzPersistence "openiam/internal/authz/adapter/outbound/persistence"
	authzApp "openiam/internal/authz/application"
	authzQuery "openiam/internal/authz/application/query"
	authzDomain "openiam/internal/authz/domain"

	identityRest "openiam/internal/identity/adapter/inbound/rest"
	identityPersistence "openiam/internal/identity/adapter/outbound/persistence"
	identityApp "openiam/internal/identity/application"

	tenantRest "openiam/internal/tenant/adapter/inbound/rest"
	tenantPersistence "openiam/internal/tenant/adapter/outbound/persistence"
	tenantApp "openiam/internal/tenant/application"

	shared "openiam/internal/shared/domain"
	sharedAuth "openiam/internal/shared/auth"
	"openiam/internal/shared/infra/eventbus"
	"openiam/internal/shared/infra/persistence"

	mw "openiam/pkg/middleware"
)

type Config struct {
	DatabaseDSN     string
	RedisAddr       string
	RedisPassword   string
	RedisDB         int
	JWTSecret       string
	JWTIssuer       string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	SessionTTL      time.Duration

	// SIWEDomain is the domain validated against the SIWE message (e.g. "example.com").
	// Leave empty to disable the SIWE strategy.
	SIWEDomain string

	// WebAuthn / Passkey configuration. Enabled when both RPID and RPOrigins are set.
	// WebAuthnRPID is the Relying Party identifier, typically the domain without scheme or port (e.g. "example.com").
	WebAuthnRPID string
	// WebAuthnRPName is the human-readable site name shown to the user (e.g. "Example Inc.").
	WebAuthnRPName string
	// WebAuthnRPOrigins is the list of permitted origins (e.g. ["https://example.com"]).
	WebAuthnRPOrigins []string
}

type Engine struct {
	Identity *identityApp.IdentityService
	Authn    *authnApp.AuthnAppService
	Authz    *authzApp.AuthzAppService
	Tenant   *tenantApp.TenantAppService
	EventBus shared.EventBus

	router chi.Router
	db     *sqlx.DB
	redis  *redis.Client
	logger *slog.Logger
}

func New(cfg Config, logger *slog.Logger) (*Engine, error) {
	if logger == nil {
		logger = slog.Default()
	}

	db, err := sqlx.Connect("postgres", cfg.DatabaseDSN)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	if err = rdb.Ping(context.Background()).Err(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect redis: %w", err)
	}

	bus := eventbus.NewMemoryEventBus(logger)
	txMgr := persistence.NewTxManager(db)

	// --- Identity ---
	userRepo := identityPersistence.NewPostgresUserRepository(db)
	identitySvc := identityApp.NewIdentityService(userRepo, bus, txMgr)

	// --- Authn ---
	credRepo := authnPersistence.NewPostgresCredentialRepo(db)
	sessionRepo := authnPersistence.NewRedisSessionRepo(rdb)
	challengeStore := authnPersistence.NewRedisChallengeStore(rdb)

	jwtProvider := authnToken.NewJWTProvider(authnToken.JWTConfig{
		Secret:         cfg.JWTSecret,
		Issuer:         cfg.JWTIssuer,
		AccessTokenTTL: cfg.AccessTokenTTL,
	})

	identityAdapter := &identityBridgeAdapter{svc: identitySvc}

	sessionTTL := cfg.SessionTTL
	if sessionTTL == 0 {
		sessionTTL = cfg.RefreshTokenTTL
	}
	if sessionTTL == 0 {
		sessionTTL = 7 * 24 * time.Hour
	}

	authnOpts := []authnApp.Option{
		authnApp.WithPasswordAuth(credRepo, identityAdapter),
		authnApp.WithRegistrar(identityAdapter),
	}

	if cfg.SIWEDomain != "" {
		authnOpts = append(authnOpts, authnApp.WithSIWEAuth(
			authnStrategy.SIWEConfig{Domain: cfg.SIWEDomain},
			credRepo, identityAdapter, identityAdapter, challengeStore,
		))
	}

	if cfg.WebAuthnRPID != "" && len(cfg.WebAuthnRPOrigins) > 0 {
		authnOpts = append(authnOpts, authnApp.WithWebAuthnAuth(
			authnStrategy.WebAuthnConfig{
				RPID:          cfg.WebAuthnRPID,
				RPDisplayName: cfg.WebAuthnRPName,
				RPOrigins:     cfg.WebAuthnRPOrigins,
			},
			credRepo, identityAdapter, identityAdapter, challengeStore,
		))
	}

	authnSvc, err := authnApp.NewAuthnAppService(
		sessionRepo, jwtProvider, bus, sessionTTL, logger,
		authnOpts...,
	)
	if err != nil {
		_ = db.Close()
		_ = rdb.Close()
		return nil, fmt.Errorf("init authn service: %w", err)
	}
	authnHandler := authnRest.NewHandler(authnSvc, jwtProvider)

	authnSub := authnEvent.NewSubscriber(credRepo, logger)
	if err := authnSub.Register(bus); err != nil {
		_ = db.Close()
		_ = rdb.Close()
		return nil, fmt.Errorf("register authn event subscriber: %w", err)
	}

	// --- Authz ---
	roleRepo := authzPersistence.NewPostgresRoleRepository(db)
	resPermRepo := authzPersistence.NewPostgresResourcePermissionRepository(db)
	permDefRepo := authzPersistence.NewPostgresPermissionDefinitionRepository(db)
	enforcer := authzDomain.NewEnforcer(roleRepo, resPermRepo)
	authzSvc := authzApp.NewAuthzAppService(roleRepo, resPermRepo, permDefRepo, enforcer, bus, txMgr)

	// Protocol-agnostic permission checker — shared by all adapters.
	accessCheck := sharedAuth.Checker(func(ctx context.Context, resource, action string) error {
		claims, ok := sharedAuth.ClaimsFromContext(ctx)
		if !ok {
			return shared.ErrUnauthorized
		}
		appID := claims.AppID
		if appID == "" {
			appID = "default"
		}
		result, err := authzSvc.CheckPermission(ctx, &authzQuery.CheckPermission{
			UserID:   claims.UserID,
			AppID:    appID,
			Resource: resource,
			Action:   action,
		})
		if err != nil {
			return err
		}
		if !result.Allowed {
			return shared.ErrForbidden
		}
		return nil
	})

	authzHandler := authzRest.NewHandler(authzSvc, accessCheck)
	identityHandler := identityRest.NewHandler(identitySvc, accessCheck)

	authzSub := authzEvent.NewSubscriber(roleRepo, permDefRepo, bus, txMgr)
	if err = authzSub.Register(); err != nil {
		_ = db.Close()
		_ = rdb.Close()
		return nil, fmt.Errorf("register authz event subscriber: %w", err)
	}

	// --- Tenant ---
	tenantRepo := tenantPersistence.NewPostgresTenantRepository(db)
	appRepo := tenantPersistence.NewPostgresApplicationRepository(db)
	tenantSvc := tenantApp.NewTenantAppService(tenantRepo, appRepo, bus, txMgr)
	tenantHandler := tenantRest.NewHandler(tenantSvc, accessCheck)

	// --- Router ---
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Mount("/__test/authn", http.StripPrefix("/__test/authn", testAuthnPageHandler()))

	r.Route("/api/v1", func(api chi.Router) {
		api.Mount("/auth", authnHandler.Routes())

		api.Group(func(protected chi.Router) {
			protected.Use(mw.BearerAuth(jwtProvider))
			protected.Mount("/tenants", tenantHandler.TenantRoutes())
			protected.Mount("/applications", tenantHandler.ApplicationRoutes())
			protected.Mount("/users", identityHandler.Routes())
			protected.Mount("/authz", authzHandler.Routes())
		})
	})

	return &Engine{
		Identity: identitySvc,
		Authn:    authnSvc,
		Authz:    authzSvc,
		Tenant:   tenantSvc,
		EventBus: bus,
		router:   r,
		db:       db,
		redis:    rdb,
		logger:   logger,
	}, nil
}

func (e *Engine) Handler() http.Handler {
	return e.router
}

func (e *Engine) Close() error {
	dbErr := e.db.Close()
	redisErr := e.redis.Close()
	if dbErr != nil {
		return dbErr
	}
	return redisErr
}
