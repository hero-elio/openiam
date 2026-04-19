package application

import (
	"fmt"

	"openiam/internal/authn/adapter/outbound/strategy"
	"openiam/internal/authn/domain"
)

func WithPasswordAuth(credRepo domain.CredentialRepository, userProvider domain.UserInfoProvider) Option {
	return func(svc *AuthnAppService) error {
		svc.strategies[domain.CredentialPassword] = strategy.NewPasswordStrategy(credRepo, userProvider)
		return nil
	}
}

func WithSIWEAuth(cfg strategy.SIWEConfig, credRepo domain.CredentialRepository, identity domain.ExternalLoginIdentity, store domain.ChallengeStore) Option {
	return func(svc *AuthnAppService) error {
		svc.strategies[domain.CredentialSIWE] = strategy.NewSIWEStrategy(cfg, credRepo, identity, store)
		return nil
	}
}

func WithWebAuthnAuth(cfg strategy.WebAuthnConfig, credRepo domain.CredentialRepository, identity domain.ExternalLoginIdentity, store domain.ChallengeStore) Option {
	return func(svc *AuthnAppService) error {
		s, err := strategy.NewWebAuthnStrategy(cfg, credRepo, identity, store)
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
