package domain

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	shared "openiam/internal/shared/domain"
)

// ApplicationUpdate describes the optional mutations callers can apply to
// an existing application. A nil slice means "leave unchanged"; an empty
// (non-nil) slice means "clear". An empty Name means "leave unchanged".
type ApplicationUpdate struct {
	Name         string
	RedirectURIs []string
	Scopes       []string
}

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

// ApplyUpdate mutates the application with the provided fields and records
// an ApplicationUpdatedEvent if anything actually changed. Returns true
// when the aggregate was mutated.
func (a *Application) ApplyUpdate(u ApplicationUpdate) bool {
	changed := false

	if name := strings.TrimSpace(u.Name); name != "" && name != a.Name {
		a.Name = name
		changed = true
	}
	if u.RedirectURIs != nil && !sliceEqual(a.RedirectURIs, u.RedirectURIs) {
		a.RedirectURIs = append([]string(nil), u.RedirectURIs...)
		changed = true
	}
	if u.Scopes != nil && !sliceEqual(a.Scopes, u.Scopes) {
		a.Scopes = append([]string(nil), u.Scopes...)
		changed = true
	}

	if !changed {
		return false
	}

	a.RecordEvent(ApplicationUpdatedEvent{
		AppID:        a.ID,
		TenantID:     a.TenantID,
		Name:         a.Name,
		RedirectURIs: append([]string(nil), a.RedirectURIs...),
		Scopes:       append([]string(nil), a.Scopes...),
		Timestamp:    time.Now(),
	})
	return true
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
