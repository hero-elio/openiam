package domain

import (
	"context"

	shared "openiam/internal/shared/domain"
)

type CredentialRepository interface {
	Save(ctx context.Context, cred *Credential) error
	FindByID(ctx context.Context, id shared.CredentialID) (*Credential, error)
	FindByUserAndType(ctx context.Context, userID shared.UserID, appID shared.AppID, credType CredentialType) (*Credential, error)
	FindBySubjectAndType(ctx context.Context, subject string, appID shared.AppID, credType CredentialType) (*Credential, error)
	Update(ctx context.Context, cred *Credential) error
	Delete(ctx context.Context, id shared.CredentialID) error
	ListByUser(ctx context.Context, userID shared.UserID) ([]*Credential, error)
}
