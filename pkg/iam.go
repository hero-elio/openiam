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
	authzDomain "openiam/internal/authz/domain"

	identityRest "openiam/internal/identity/adapter/inbound/rest"
	identityPersistence "openiam/internal/identity/adapter/outbound/persistence"
	identityApp "openiam/internal/identity/application"

	shared "openiam/internal/shared/domain"
	"openiam/internal/shared/infra/eventbus"
	"openiam/internal/shared/infra/persistence"
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

	SIWEDomain        string
	WebAuthnRPID      string
	WebAuthnRPName    string
	WebAuthnRPOrigins []string
}

type Engine struct {
	Identity *identityApp.IdentityService
	Authn    *authnApp.AuthnAppService
	Authz    *authzApp.AuthzAppService
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
	identityHandler := identityRest.NewHandler(identitySvc)

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
			credRepo, identityAdapter, challengeStore,
		))
	}

	if cfg.WebAuthnRPID != "" && len(cfg.WebAuthnRPOrigins) > 0 {
		authnOpts = append(authnOpts, authnApp.WithWebAuthnAuth(
			authnStrategy.WebAuthnConfig{
				RPID:          cfg.WebAuthnRPID,
				RPDisplayName: cfg.WebAuthnRPName,
				RPOrigins:     cfg.WebAuthnRPOrigins,
			},
			credRepo, identityAdapter, challengeStore,
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
	enforcer := authzDomain.NewEnforcer(roleRepo)
	authzSvc := authzApp.NewAuthzAppService(roleRepo, enforcer, bus, txMgr)
	authzHandler := authzRest.NewHandler(authzSvc)

	authzSub := authzEvent.NewSubscriber(roleRepo, bus)
	if err = authzSub.Register(); err != nil {
		_ = db.Close()
		_ = rdb.Close()
		return nil, fmt.Errorf("register authz event subscriber: %w", err)
	}

	// --- Router ---
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Route("/api/v1", func(api chi.Router) {
		api.Mount("/users", identityHandler.Routes())
		api.Mount("/auth", authnHandler.Routes())
		api.Mount("/authz", authzHandler.Routes())
	})

	return &Engine{
		Identity: identitySvc,
		Authn:    authnSvc,
		Authz:    authzSvc,
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
