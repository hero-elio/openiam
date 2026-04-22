// Package memory provides goroutine-safe, in-process implementations of
// every outbound port the IAM modules consume. The package exists for
// two reasons:
//
//  1. SDK consumers can spin up a fully working IAM stack without any
//     external infrastructure — useful for tests, CLIs, ephemeral
//     preview environments, and "kick the tyres" scripts.
//
//  2. The smoke test that ships in this package proves the public
//     module interfaces (pkg/iam/authn, pkg/iam/identity) are coherent:
//     register → login → refresh → list-sessions runs end-to-end with
//     zero database, zero Redis, zero JWT keys to manage.
//
// Typical use:
//
//	mem := memory.New()
//	identityMod, _ := identity.New(identity.Config{}, identity.Deps{
//	    Users:     mem.Users,
//	    EventBus:  bus,
//	    TxManager: mem.TxManager,
//	})
//	authnMod, _ := authn.New(authn.Config{
//	    JWTSecret:              "test-secret-at-least-32-bytes-xxx",
//	    AccessTokenTTL:         15 * time.Minute,
//	    SessionTTL:             24 * time.Hour,
//	    AllowInsecureJWTSecret: true,
//	}, authn.Deps{
//	    Credentials:   mem.Credentials,
//	    Sessions:      mem.Sessions,
//	    Challenges:    mem.Challenges,
//	    EventBus:      bus,
//	    Identity:      identity.IntegrationFor(identityMod.Service),
//	    TokenProvider: jwt.TokenProvider(jwt.Config{Secret: "...", Issuer: "test", AccessTokenTTL: 15 * time.Minute}),
//	    RateLimiter:   authn.NoOpRateLimiter{},
//	})
//
// All stores are concurrency-safe and copy values on read/write so
// callers cannot accidentally mutate the storage's internal state.
//
// The package is explicitly not intended for production: it never
// expires entries on its own (challenges respect TTLs, but credentials
// and sessions live until the process dies), it has no persistence,
// and it does not enforce uniqueness constraints across processes.
package memory

import (
	"openiam/pkg/iam/authn"
	"openiam/pkg/iam/identity"
)

// AdapterSet bundles every in-memory port implementation IAM ships
// with. Each field is the public port type from the corresponding
// pkg/iam/<module> package, so wiring is a drop-in replacement for
// pkg/iam/adapters/postgres.AdapterSet (modulo the modules that don't
// have an in-memory backing yet).
type AdapterSet struct {
	// authn ports
	Credentials authn.CredentialStore
	Sessions    authn.SessionStore
	Challenges  authn.ChallengeStore
	RateLimiter authn.RateLimiter

	// identity ports
	Users     identity.UserStore
	TxManager TxManager
}

// New returns a fresh AdapterSet with empty backing maps. Each call
// creates independent stores; sharing state across modules requires
// reusing the same AdapterSet.
func New() AdapterSet {
	return AdapterSet{
		Credentials: NewCredentialStore(),
		Sessions:    NewSessionStore(),
		Challenges:  NewChallengeStore(),
		RateLimiter: authn.NoOpRateLimiter{},
		Users:       NewUserStore(),
		TxManager:   NewTxManager(),
	}
}
