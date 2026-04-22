# OpenIAM

Composable Identity & Access Management SDK for Go.

OpenIAM is a small set of Go packages that you can either run as a standalone
HTTP server (`cmd/iam-server`) or embed into your own application as a library.
Each module — `authn`, `identity`, `authz`, `tenant` — is independently usable
and exposes a transport-agnostic `Service` interface plus a strict set of port
interfaces that you implement (or re-use one of the built-in adapters).

```text
pkg/iam/                       SDK public surface
├── iam.go                     Engine + Builder (batteries included)
├── authn/                     Service + Config/Deps + ports
├── identity/                  Service + Config/Deps + ports
├── authz/                     Service + Config/Deps + ports + Checker
├── tenant/                    Service + Config/Deps + ports
├── eventbus/                  In-memory + outbox event bus
├── sharedauth/                Claims + Checker shared types
├── transport/rest/            chi-based HTTP mounters + middleware
└── adapters/
    ├── postgres/              All Postgres-backed repositories
    ├── redis/                 Sessions / challenges / rate limiter
    ├── jwt/                   HMAC-JWT token provider
    └── memory/                Fully in-memory ports (tests / embedded use)
```

## Three usage styles

### 1. Batteries included — `iam.New(Config{...})`

The fastest way to get the full IAM stack with HTTP routes wired up. Used by
`cmd/iam-server`, but suitable for any service that needs the standard set of
endpoints.

```go
import (
    "log/slog"
    "net/http"
    "time"

    "openiam/pkg/iam"
    "openiam/pkg/iam/authn"
)

func main() {
    engine, err := iam.New(iam.Config{
        Logger:   slog.Default(),
        Postgres: &iam.PostgresConfig{DSN: "postgres://localhost/iam?sslmode=disable"},
        Redis:    &iam.RedisConfig{Addr: "localhost:6379"},
        Tenant:   &iam.TenantConfig{},
        Identity: &iam.IdentityConfig{},
        Authz:    &iam.AuthzConfig{},
        Authn: &iam.AuthnConfig{
            Config: authn.Config{
                JWTSecret:      "change-me-in-production-please-32+chars",
                JWTIssuer:      "openiam",
                AccessTokenTTL: 15 * time.Minute,
                SessionTTL:     24 * time.Hour,
            },
        },
    })
    if err != nil {
        panic(err)
    }
    defer engine.Close()

    http.ListenAndServe(":8080", engine.Handler())
}
```

`iam.New` returns an `*Engine` whose module fields (`engine.Authn`,
`engine.Identity`, …) are nil for every section you omitted from `Config`,
so you can install only the subset you need.

### 2. Compose your own — per-module packages

When you want to skip the bundled HTTP transport, mount routes under a custom
path scheme, or only need one or two modules, build the modules directly. Each
`pkg/iam/<module>.New` accepts a `Deps` struct of port interfaces and returns a
`*Module` whose `Service` field implements the public service interface.

```go
import (
    "openiam/pkg/iam/adapters/jwt"
    "openiam/pkg/iam/adapters/postgres"
    redisAdapters "openiam/pkg/iam/adapters/redis"
    "openiam/pkg/iam/authn"
    "openiam/pkg/iam/eventbus"
    "openiam/pkg/iam/identity"
    "openiam/pkg/iam/transport/rest"
)

pg := postgres.Adapters(db)              // every Postgres repository at once
rd := redisAdapters.AuthnAdapters(rdb)   // sessions / challenges / rate limiter
bus := eventbus.NewMemory(logger)
txMgr := postgres.TxManager(db)

identityMod, _ := identity.New(identity.Config{}, identity.Deps{
    Users:     pg.Users,
    EventBus:  bus,
    TxManager: txMgr,
})

authnMod, _ := authn.New(
    authn.Config{
        JWTSecret:      secret,
        JWTIssuer:      "my-app",
        AccessTokenTTL: 15 * time.Minute,
        SessionTTL:     24 * time.Hour,
    },
    authn.Deps{
        Credentials:   pg.Credentials,
        Sessions:      rd.Sessions,
        Challenges:    rd.Challenges,
        RateLimiter:   rd.RateLimiter,
        TokenProvider: jwt.TokenProvider(jwt.Config{Secret: secret, Issuer: "my-app", AccessTokenTTL: 15 * time.Minute}),
        Identity:      identity.IntegrationFor(identityMod.Service),
        EventBus:      bus,
    },
)

r := chi.NewRouter()
rest.MountAuthn(r, authnMod.Service)
rest.MountIdentity(r, identityMod.Service, allowAll /* sharedauth.Checker */)
```

Cross-module wiring goes through the small adapter functions each module
exposes:

- `identity.IntegrationFor(svc)` produces the `authn.IdentityIntegration`
  authn needs for registration flows.
- `tenant.AppDirectoryFor(svc)` produces the `authn.AppDirectory` SIWE /
  WebAuthn use to find the tenant for an app.
- `tenant.ScopeValidatorFor(svc)` produces the `identity.ScopeValidator`
  that gates user creation by tenant/app.
- `identity.SubjectExistenceFor(svc)` and `tenant.SubjectExistenceFor(svc)`
  feed `authz.ComposeSubjectExistence(users, apps)` so authz can reject
  grants for unknown subjects.

If a module is missing in your deployment, hand authz an explicit
`authz.NoOpSubjectExistence{}` to opt out of the pre-check.

### 3. Bring your own storage — implement the ports

Every module documents a small set of port interfaces in
`pkg/iam/<module>/ports.go`. Implement them against any backend you like and
inject them through `Deps`:

```go
type myCredentialStore struct{ /* … */ }
func (s *myCredentialStore) Save(ctx context.Context, c *authn.Credential) error { /* … */ }
func (s *myCredentialStore) FindByUserID(ctx context.Context, userID shared.UserID) (*authn.Credential, error) { /* … */ }
// … etc

authnMod, _ := authn.New(authn.Config{...}, authn.Deps{
    Credentials: &myCredentialStore{},
    Sessions:    &myRedisLikeSessionStore{},
    // …
})
```

`pkg/iam/adapters/memory` ships a complete in-memory implementation of every
authn / identity port. It doubles as a reference implementation and powers the
`pkg/iam/adapters/memory/smoke_test.go` end-to-end test that proves the SDK
runs with zero external dependencies.

## HTTP routes

When mounted via `iam.Engine.Handler()` the default layout is:

| Prefix                   | Module   | Notes                              |
| ------------------------ | -------- | ---------------------------------- |
| `/healthz`               | —        | Liveness probe (always 200)        |
| `/readyz`                | —        | Pings configured DB / Redis        |
| `/api/v1/auth/*`         | authn    | Public; no bearer required         |
| `/api/v1/users/*`        | identity | Bearer + permission checks         |
| `/api/v1/authz/*`        | authz    | Bearer + permission checks         |
| `/api/v1/tenants/*`      | tenant   | Bearer + permission checks         |
| `/api/v1/applications/*` | tenant   | Bearer + permission checks         |
| `/__test/authn`          | authn    | Mounted only when authn is enabled |

Custom routers can call the same `pkg/iam/transport/rest.Mount*` helpers
directly with their own prefixes.

## Design documents

Architecture and bounded-context design lives under `docs/design/`. Start with
`docs/design/README.md` for the reading order.
