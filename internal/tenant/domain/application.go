package domain

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	shared "openiam/internal/shared/domain"
)

type Application struct {
	shared.AggregateRoot
	ID               shared.AppID
	TenantID         shared.TenantID
	Name             string
	ClientID         string
	ClientSecretHash string
	RedirectURIs     []string
	Scopes           []string
	Status           string
	CreatedAt        time.Time
}

type ClientCredentials struct {
	ClientID     string
	ClientSecret string
	SecretHash   string
}

func GenerateClientCredentials() ClientCredentials {
	id := randomHex(16)
	secret := randomHex(32)
	hash := sha256Hex(secret)
	return ClientCredentials{
		ClientID:     id,
		ClientSecret: secret,
		SecretHash:   hash,
	}
}

func NewApplication(tenantID shared.TenantID, name string, creds ClientCredentials, createdBy shared.UserID) *Application {
	now := time.Now()
	app := &Application{
		ID:               shared.NewAppID(),
		TenantID:         tenantID,
		Name:             name,
		ClientID:         creds.ClientID,
		ClientSecretHash: creds.SecretHash,
		RedirectURIs:     []string{},
		Scopes:           []string{},
		Status:           "active",
		CreatedAt:        now,
	}
	app.RecordEvent(ApplicationCreatedEvent{
		AppID:     app.ID,
		TenantID:  tenantID,
		Name:      name,
		CreatedBy: createdBy,
		Timestamp: now,
	})
	return app
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
