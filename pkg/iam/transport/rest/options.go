package rest

import (
	"net/http"
)

// Option customizes a Mount<Module> call. Options are intentionally
// few and orthogonal — anything more invasive belongs in a custom
// transport built on top of the public Service interface.
type Option func(*mountConfig)

type mountConfig struct {
	pathPrefix     string
	skipEndpoints  map[string]struct{}
	extraMiddleware []func(http.Handler) http.Handler
}

func newMountConfig(opts []Option) *mountConfig {
	c := &mountConfig{
		skipEndpoints: make(map[string]struct{}),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *mountConfig) skipped(name string) bool {
	_, ok := c.skipEndpoints[name]
	return ok
}

// WithPathPrefix nests the mounted routes under prefix. When empty,
// the module's default path layout is used.
//
// Example: WithPathPrefix("/v2/auth") mounts the authn routes under
// /v2/auth/login etc.
func WithPathPrefix(prefix string) Option {
	return func(c *mountConfig) { c.pathPrefix = prefix }
}

// SkipEndpoints disables specific endpoints by their stable name (each
// Mount<Module> documents its endpoint names). Useful when the SDK
// consumer wants to expose only a subset of the module's surface or
// supply its own implementation for one of the routes.
func SkipEndpoints(names ...string) Option {
	return func(c *mountConfig) {
		for _, n := range names {
			c.skipEndpoints[n] = struct{}{}
		}
	}
}

// WithMiddleware adds chi-style middleware that runs for every route
// the Mount call registers. Useful for per-module logging, metrics,
// CORS, etc.
func WithMiddleware(mw ...func(http.Handler) http.Handler) Option {
	return func(c *mountConfig) {
		c.extraMiddleware = append(c.extraMiddleware, mw...)
	}
}
