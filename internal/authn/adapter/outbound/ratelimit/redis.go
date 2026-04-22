// Package ratelimit contains adapters that implement
// authn/domain.RateLimiter against external infrastructure.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis implements domain.RateLimiter as a fixed-window counter:
//
//	INCR <prefix>:<key>:<window-bucket>
//	EXPIRE on first hit (NX) so the key always cleans itself up
//
// We deliberately keep the algorithm trivial — a fixed window is the
// cheapest reliable option (one INCR + maybe one EXPIRE per request) and
// it gives a strict upper bound: at most `limit` calls per `window`. The
// trade-off is a 2x burst at window boundaries, which is acceptable for
// login throttling.
type Redis struct {
	rdb    *redis.Client
	prefix string
}

func NewRedis(rdb *redis.Client) *Redis {
	return NewRedisWithPrefix(rdb, "ratelimit")
}

func NewRedisWithPrefix(rdb *redis.Client, prefix string) *Redis {
	return &Redis{rdb: rdb, prefix: prefix}
}

func (r *Redis) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, time.Duration, error) {
	if r == nil || r.rdb == nil {
		// A nil limiter means "rate limiting disabled" — never block.
		return true, 0, nil
	}
	if limit <= 0 || window <= 0 {
		return true, 0, nil
	}

	bucket := time.Now().UnixNano() / window.Nanoseconds()
	redisKey := fmt.Sprintf("%s:%s:%d", r.prefix, key, bucket)

	count, err := r.rdb.Incr(ctx, redisKey).Result()
	if err != nil {
		return false, 0, fmt.Errorf("rate limit incr: %w", err)
	}

	if count == 1 {
		// First write into this window — give it an expiry so the key
		// disappears after the bucket rolls over. Ignore failures: the
		// counter is still correct, we just leak one key for `window`.
		_ = r.rdb.Expire(ctx, redisKey, window).Err()
	}

	if count > int64(limit) {
		ttl, ttlErr := r.rdb.TTL(ctx, redisKey).Result()
		if ttlErr != nil || ttl < 0 {
			ttl = window
		}
		return false, ttl, nil
	}

	return true, 0, nil
}

// IsRedisError lets handlers tell "limiter unavailable" apart from "over
// budget" when they want to fail-open on infra outages instead of
// blocking real users on a Redis blip.
func IsRedisError(err error) bool {
	var rerr redis.Error
	return errors.As(err, &rerr)
}
