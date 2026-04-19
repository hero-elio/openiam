package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	shared "openiam/internal/shared/domain"
)

func TestGenerateClientCredentials(t *testing.T) {
	creds := GenerateClientCredentials()

	if len(creds.ClientID) != 32 {
		t.Fatalf("unexpected client id length: got %d, want 32", len(creds.ClientID))
	}
	if len(creds.ClientSecret) != 64 {
		t.Fatalf("unexpected client secret length: got %d, want 64", len(creds.ClientSecret))
	}
	if creds.SecretHash == "" {
		t.Fatal("secret hash should not be empty")
	}

	h := sha256.Sum256([]byte(creds.ClientSecret))
	expected := hex.EncodeToString(h[:])
	if creds.SecretHash != expected {
		t.Fatalf("secret hash mismatch: got %q, want %q", creds.SecretHash, expected)
	}
}

func TestNewApplication_SetsDefaultsAndRecordsEvent(t *testing.T) {
	tenantID := shared.NewTenantID()
	createdBy := shared.NewUserID()
	creds := GenerateClientCredentials()

	app := NewApplication(tenantID, "demo-app", creds, createdBy)

	if app.TenantID != tenantID {
		t.Fatalf("tenant mismatch: got %q, want %q", app.TenantID, tenantID)
	}
	if app.Status != "active" {
		t.Fatalf("status mismatch: got %q, want active", app.Status)
	}
	if len(app.RedirectURIs) != 0 || len(app.Scopes) != 0 {
		t.Fatalf("new app should start with empty redirect uris/scopes")
	}
	if app.ClientSecretHash != creds.SecretHash {
		t.Fatalf("client secret hash mismatch: got %q, want %q", app.ClientSecretHash, creds.SecretHash)
	}

	events := app.PullEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 domain event, got %d", len(events))
	}

	evt, ok := events[0].(ApplicationCreatedEvent)
	if !ok {
		t.Fatalf("unexpected event type: %T", events[0])
	}
	if evt.AppID != app.ID || evt.TenantID != tenantID || evt.CreatedBy != createdBy {
		t.Fatalf("application created event payload mismatch")
	}
}
