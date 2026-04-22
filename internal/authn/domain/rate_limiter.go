package domain

import (
	"context"
	"fmt"
	"time"
)

// RateLimitedError is returned by the application layer when a request
// (most notably login) is over its budget. Transports translate it to
// their own status convention — e.g. HTTP 429 with Retry-After — so
// throttling policy stays in one place across REST, gRPC, etc.
type RateLimitedError struct {
	// Scope identifies the bucket that overflowed (e.g. "ip", "subject")
	// for logging / audit purposes. Not exposed to end users.
	Scope string
	// RetryAfter is how long the caller should wait before trying again.
	// Always > 0 when this error is returned.
	RetryAfter time.Duration
}

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("rate limited (%s): retry after %s", e.Scope, e.RetryAfter)
}

// RateLimiter is the outbound port the authn context uses to throttle
// abusive login traffic. Implementations are expected to be:
//   - distributed-safe (multiple instances must agree on a counter), and
//   - cheap enough to call on every request (fixed-window counters or
//     similar; no per-call DB transactions).
//
// Allow returns:
//   - allowed=true when the call should proceed.
//   - allowed=false plus retryAfter > 0 when the caller is over budget;
//     handlers should surface retryAfter as the Retry-After response
//     header so clients back off intelligently.
//
// A nil RateLimiter is a valid "limits disabled" implementation; callers
// must guard against it. See NoopRateLimiter for the explicit variant.
type RateLimiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (allowed bool, retryAfter time.Duration, err error)
}

// NoopRateLimiter never blocks. Useful for tests and for production
// deployments that explicitly opt out of throttling.
type NoopRateLimiter struct{}

func (NoopRateLimiter) Allow(context.Context, string, int, time.Duration) (bool, time.Duration, error) {
	return true, 0, nil
}
