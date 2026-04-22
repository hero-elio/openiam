// Package redis bundles the Redis-backed authn ports — sessions,
// challenges, and rate limiting — so SDK consumers can wire them in
// one call.
//
// Typical use:
//
//	r := redis.AuthnAdapters(rdb)
//	authn.New(cfg, authn.Deps{
//	    SessionStore:   r.Sessions,
//	    ChallengeStore: r.Challenges,
//	    RateLimiter:    r.RateLimiter,
//	    // ... other deps
//	})
//
// All three implementations share the same redis.Client; if separate
// connection pools are required, call the underlying constructors
// (NewSessions, NewChallenges, NewRateLimiter) individually.
package redis

import (
	goredis "github.com/redis/go-redis/v9"

	authnPersistence "openiam/internal/authn/adapter/outbound/persistence"
	authnRateLimit "openiam/internal/authn/adapter/outbound/ratelimit"

	"openiam/pkg/iam/authn"
)

// AuthnAdapterSet groups the Redis-backed authn ports.
type AuthnAdapterSet struct {
	Sessions    authn.SessionStore
	Challenges  authn.ChallengeStore
	RateLimiter authn.RateLimiter
}

// AuthnAdapters returns Redis-backed implementations of every authn
// port that benefits from a fast key/value store. Pass the result
// straight into authn.Deps.
func AuthnAdapters(rdb *goredis.Client) AuthnAdapterSet {
	return AuthnAdapterSet{
		Sessions:    authnPersistence.NewRedisSessionRepo(rdb),
		Challenges:  authnPersistence.NewRedisChallengeStore(rdb),
		RateLimiter: authnRateLimit.NewRedis(rdb),
	}
}

// NewSessions returns just the session store. Useful when the SDK
// consumer wires the other ports differently (e.g. a Postgres-backed
// session store for audit reasons).
func NewSessions(rdb *goredis.Client) authn.SessionStore {
	return authnPersistence.NewRedisSessionRepo(rdb)
}

// NewChallenges returns just the challenge store.
func NewChallenges(rdb *goredis.Client) authn.ChallengeStore {
	return authnPersistence.NewRedisChallengeStore(rdb)
}

// NewRateLimiter returns the Redis fixed-window rate limiter.
func NewRateLimiter(rdb *goredis.Client) authn.RateLimiter {
	return authnRateLimit.NewRedis(rdb)
}
