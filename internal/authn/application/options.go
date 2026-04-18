package application

import (
	"openiam/internal/authn/adapter/outbound/strategy"
	"openiam/internal/authn/domain"
)

func WithPasswordAuth(credRepo domain.CredentialRepository, userProvider domain.UserInfoProvider) Option {
	return func(svc *AuthnAppService) error {
		svc.strategies[domain.CredentialPassword] = strategy.NewPasswordStrategy(credRepo, userProvider)
		return nil
	}
}

func WithRegistrar(r domain.UserRegistrar) Option {
	return func(svc *AuthnAppService) error {
		svc.registrar = r
		return nil
	}
}
