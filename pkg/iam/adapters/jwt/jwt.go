// Package jwt is the SDK-facing wrapper around the HMAC-JWT
// implementation of authn.TokenProvider that ships with IAM.
//
// Typical use:
//
//	tp := jwt.TokenProvider(jwt.Config{
//	    Secret:         os.Getenv("IAM_JWT_SECRET"),
//	    Issuer:         "iam.example.com",
//	    AccessTokenTTL: 15 * time.Minute,
//	})
//	authn.New(authnCfg, authn.Deps{TokenProvider: tp, ...})
//
// SDK consumers who need a different signing scheme (RSA, EdDSA,
// PASETO, opaque tokens with Redis lookup, …) can implement
// authn.TokenProvider directly — this package just bundles the
// default.
package jwt

import (
	authnToken "openiam/internal/authn/adapter/outbound/token"

	"openiam/pkg/iam/authn"
)

// Config is the public configuration for the bundled JWT provider.
// Mirrors the internal token.JWTConfig so SDK consumers don't need to
// reach into internal/*.
type Config = authnToken.JWTConfig

// TokenProvider returns the HMAC-SHA256 JWT-backed authn.TokenProvider
// configured with cfg. Callers should validate cfg.Secret beforehand
// (or rely on authn.New's strong-secret check, which already refuses
// short / placeholder secrets unless AllowInsecureJWTSecret is set).
func TokenProvider(cfg Config) authn.TokenProvider {
	return authnToken.NewJWTProvider(cfg)
}
