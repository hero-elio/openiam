package authn

import (
	"context"
	"fmt"
	"time"

	"openiam/internal/authn/domain"
	shared "openiam/internal/shared/domain"
)

// NoOpRateLimiter never blocks. It's the default Deps.RateLimiter when
// callers leave that field nil; passing it explicitly is the documented
// way to make "throttling intentionally disabled" visible in deployment
// configs.
type NoOpRateLimiter = domain.NoopRateLimiter

// NoOpAppDirectory is the explicit "no apps registered" stand-in for
// deployments that don't want to wire the tenant module. SIWE and
// WebAuthn require a real AppDirectory so they can resolve an app's
// owning tenant before provisioning external users; calling TenantOf
// on this implementation always fails so a misconfiguration surfaces
// immediately.
type NoOpAppDirectory struct{}

func (NoOpAppDirectory) TenantOf(_ context.Context, appID shared.AppID) (shared.TenantID, error) {
	return "", fmt.Errorf("authn: no AppDirectory configured (looking up tenant for app %q)", appID)
}

// Compile-time check.
var _ AppDirectory = NoOpAppDirectory{}
var _ RateLimiter = NoOpRateLimiter{}

// _ keeps the time import alive when nothing in the file uses it
// directly; future trivial NoOps may need it.
var _ = time.Duration(0)
