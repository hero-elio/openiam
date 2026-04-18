package domain

import (
	"time"

	shared "openiam/internal/shared/domain"
)

type Credential struct {
	shared.AggregateRoot
	ID                shared.CredentialID
	UserID            shared.UserID
	AppID             shared.AppID
	Type              CredentialType
	Provider          string
	CredentialSubject string
	Secret            *string
	PublicKey         *string
	Metadata          map[string]any
	CreatedAt         time.Time
	LastUsedAt        time.Time
}

func NewCredential(userID shared.UserID, appID shared.AppID, credType CredentialType, provider, subject string) *Credential {
	now := time.Now()
	return &Credential{
		ID:                shared.NewCredentialID(),
		UserID:            userID,
		AppID:             appID,
		Type:              credType,
		Provider:          provider,
		CredentialSubject: subject,
		Metadata:          make(map[string]any),
		CreatedAt:         now,
		LastUsedAt:        now,
	}
}

func (c *Credential) MarkUsed() {
	c.LastUsedAt = time.Now()
}

func (c *Credential) SetSecret(secret string) {
	c.Secret = &secret
}

func (c *Credential) SetPublicKey(key string) {
	c.PublicKey = &key
}
