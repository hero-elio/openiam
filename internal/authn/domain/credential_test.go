package domain

import (
	"testing"
	"time"

	shared "openiam/internal/shared/domain"
)

func TestNewCredential_InitializesFields(t *testing.T) {
	userID := shared.NewUserID()
	appID := shared.NewAppID()

	cred := NewCredential(userID, appID, CredentialPassword, "local", "alice@example.com")

	if cred.ID == "" {
		t.Fatal("credential id should not be empty")
	}
	if cred.UserID != userID || cred.AppID != appID {
		t.Fatalf("credential owner mismatch")
	}
	if cred.Type != CredentialPassword {
		t.Fatalf("credential type mismatch: got %q", cred.Type)
	}
	if cred.Metadata == nil {
		t.Fatal("metadata map should be initialized")
	}
	if cred.CreatedAt.IsZero() || cred.LastUsedAt.IsZero() {
		t.Fatal("timestamps should be initialized")
	}
}

func TestCredential_SettersAndMarkUsed(t *testing.T) {
	cred := NewCredential(
		shared.NewUserID(),
		shared.NewAppID(),
		CredentialPassword,
		"local",
		"alice@example.com",
	)

	cred.SetSecret("s3cr3t")
	cred.SetPublicKey("pk")
	if cred.Secret == nil || *cred.Secret != "s3cr3t" {
		t.Fatalf("secret not set as expected")
	}
	if cred.PublicKey == nil || *cred.PublicKey != "pk" {
		t.Fatalf("public key not set as expected")
	}

	before := cred.LastUsedAt
	time.Sleep(2 * time.Millisecond)
	cred.MarkUsed()
	if !cred.LastUsedAt.After(before) {
		t.Fatalf("last used should advance: before=%v after=%v", before, cred.LastUsedAt)
	}
}
