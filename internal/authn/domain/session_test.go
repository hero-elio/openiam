package domain

import (
	"testing"
	"time"

	shared "openiam/internal/shared/domain"
)

func TestSession_IsExpired(t *testing.T) {
	expired := NewSession(
		shared.NewSessionID(),
		shared.NewUserID(),
		shared.NewTenantID(),
		shared.NewAppID(),
		"password",
		"refresh-1",
		"ua",
		"127.0.0.1",
		time.Now().Add(-time.Minute),
	)
	if !expired.IsExpired() {
		t.Fatal("expected expired session")
	}

	active := NewSession(
		shared.NewSessionID(),
		shared.NewUserID(),
		shared.NewTenantID(),
		shared.NewAppID(),
		"password",
		"refresh-2",
		"ua",
		"127.0.0.1",
		time.Now().Add(time.Minute),
	)
	if active.IsExpired() {
		t.Fatal("did not expect active session to be expired")
	}
}

func TestSession_RefreshUpdatesTokenExpiryAndLastActive(t *testing.T) {
	session := NewSession(
		shared.NewSessionID(),
		shared.NewUserID(),
		shared.NewTenantID(),
		shared.NewAppID(),
		"password",
		"old-refresh",
		"ua",
		"127.0.0.1",
		time.Now().Add(5*time.Minute),
	)

	prevLastActive := session.LastActiveAt
	newExpiry := time.Now().Add(30 * time.Minute)
	session.Refresh("new-refresh", newExpiry)

	if session.RefreshToken != "new-refresh" {
		t.Fatalf("refresh token not updated: got %q", session.RefreshToken)
	}
	if !session.ExpiresAt.Equal(newExpiry) {
		t.Fatalf("expiry mismatch: got %v, want %v", session.ExpiresAt, newExpiry)
	}
	if !session.LastActiveAt.After(prevLastActive) {
		t.Fatalf("last active should advance: before=%v after=%v", prevLastActive, session.LastActiveAt)
	}
}
