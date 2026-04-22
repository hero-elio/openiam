package application

import (
	"fmt"
	"time"

	"openiam/internal/authn/adapter/outbound/strategy"
	"openiam/internal/authn/domain"
)

func WithPasswordAuth(credRepo domain.CredentialRepository, userProvider domain.UserInfoProvider) Option {
	return func(svc *AuthnAppService) error {
		svc.strategies[domain.CredentialPassword] = strategy.NewPasswordStrategy(credRepo, userProvider)
		return nil
	}
}

func WithSIWEAuth(cfg strategy.SIWEConfig, credRepo domain.CredentialRepository, identity domain.ExternalLoginIdentity, store domain.ChallengeStore, apps domain.AppDirectory) Option {
	return func(svc *AuthnAppService) error {
		svc.strategies[domain.CredentialSIWE] = strategy.NewSIWEStrategy(cfg, credRepo, identity, store, apps)
		return nil
	}
}

func WithWebAuthnAuth(cfg strategy.WebAuthnConfig, credRepo domain.CredentialRepository, identity domain.ExternalLoginIdentity, store domain.ChallengeStore, apps domain.AppDirectory) Option {
	return func(svc *AuthnAppService) error {
		s, err := strategy.NewWebAuthnStrategy(cfg, credRepo, identity, store, apps)
		if err != nil {
			return fmt.Errorf("init webauthn strategy: %w", err)
		}
		svc.strategies[domain.CredentialWebAuthn] = s
		return nil
	}
}

func WithSMSAuth(credRepo domain.CredentialRepository, userProvider domain.UserInfoProvider, store domain.ChallengeStore, sender strategy.SMSSender) Option {
	return func(svc *AuthnAppService) error {
		svc.strategies[domain.CredentialSMS] = strategy.NewSMSStrategy(credRepo, userProvider, store, sender)
		return nil
	}
}

func WithRegistrar(r domain.UserRegistrar) Option {
	return func(svc *AuthnAppService) error {
		svc.registrar = r
		return nil
	}
}

// WithUserInfoProvider lets AuthnAppService.AuthenticateToken consult the
// identity context for the caller's current status (active / disabled /
// locked). When omitted, the token signature/expiry are still checked but
// account-state revocation requires the token to expire on its own.
func WithUserInfoProvider(p domain.UserInfoProvider) Option {
	return func(svc *AuthnAppService) error {
		svc.userInfo = p
		return nil
	}
}

// WithLoginRateLimit installs a rate limiter for AuthnAppService.Login.
// limiter==nil disables throttling entirely; pass NoopRateLimiter
// explicitly for the same effect with intent. attempts<=0 or window<=0
// fall back to the package defaults.
func WithLoginRateLimit(limiter domain.RateLimiter, attempts int, window time.Duration) Option {
	return func(svc *AuthnAppService) error {
		if limiter == nil {
			limiter = domain.NoopRateLimiter{}
		}
		svc.loginLimiter = limiter
		if attempts > 0 {
			svc.loginAttemptsBudget = attempts
		}
		if window > 0 {
			svc.loginRateWindow = window
		}
		return nil
	}
}
