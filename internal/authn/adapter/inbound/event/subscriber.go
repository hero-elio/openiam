package event

import (
	"context"
	"log/slog"

	"openiam/internal/authn/domain"
	shared "openiam/internal/shared/domain"
)

type Subscriber struct {
	credRepo domain.CredentialRepository
	logger   *slog.Logger
}

func NewSubscriber(credRepo domain.CredentialRepository, logger *slog.Logger) *Subscriber {
	if logger == nil {
		logger = slog.Default()
	}
	return &Subscriber{credRepo: credRepo, logger: logger}
}

func (s *Subscriber) Register(eventBus shared.EventBus) error {
	return eventBus.Subscribe("user.registered", s.onUserRegistered)
}

type registeredPayload interface {
	shared.DomainEvent
	GetUserID() shared.UserID
	GetAppID() shared.AppID
	GetProvider() string
	GetCredentialSubject() string
	GetSecret() string
	GetPublicKey() string
	GetTenantID() shared.TenantID
}

func (s *Subscriber) onUserRegistered(ctx context.Context, evt shared.DomainEvent) error {
	payload, ok := evt.(registeredPayload)
	if !ok {
		s.logger.WarnContext(ctx, "user.registered event payload type not recognized",
			"aggregate_id", evt.AggregateID(),
		)
		return nil
	}

	credType := domain.CredentialType(payload.GetProvider())

	cred := domain.NewCredential(
		payload.GetUserID(),
		payload.GetAppID(),
		credType,
		payload.GetProvider(),
		payload.GetCredentialSubject(),
	)

	if secret := payload.GetSecret(); secret != "" {
		cred.SetSecret(secret)
	}

	if pubKey := payload.GetPublicKey(); pubKey != "" {
		cred.SetPublicKey(pubKey)
	}

	if err := s.credRepo.Save(ctx, cred); err != nil {
		s.logger.ErrorContext(ctx, "failed to create credential",
			"user_id", payload.GetUserID(),
			"app_id", payload.GetAppID(),
			"provider", payload.GetProvider(),
			"error", err,
		)
		return err
	}

	s.logger.InfoContext(ctx, "credential created for new user",
		"user_id", payload.GetUserID(),
		"app_id", payload.GetAppID(),
		"provider", payload.GetProvider(),
	)
	return nil
}
