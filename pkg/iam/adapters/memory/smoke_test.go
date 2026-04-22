package memory_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"openiam/pkg/iam/adapters/jwt"
	"openiam/pkg/iam/adapters/memory"
	"openiam/pkg/iam/authn"
	"openiam/pkg/iam/eventbus"
	"openiam/pkg/iam/identity"
)

// TestSmoke_RegisterLoginRefresh proves the public SDK surface holds
// together end-to-end without any external infrastructure: zero DB,
// zero Redis, zero file IO.
//
// The flow exercised:
//
//  1. Wire identity + authn modules with the in-memory adapters.
//  2. Register a brand-new user via authn.Service.Register.
//  3. Login with the same credentials.
//  4. Refresh the resulting tokens.
//  5. Validate the refreshed access token via AuthenticateToken.
//  6. List the active sessions.
//
// Any drift between the public Service interfaces and the internal
// implementations breaks this test, which is why we keep it in this
// package — it doubles as living documentation of how SDK consumers
// are expected to wire things up.
func TestSmoke_RegisterLoginRefresh(t *testing.T) {
	const (
		appID    = "app-smoke"
		tenantID = "tenant-smoke"
		email    = "alice@example.com"
		password = "Sup3rSecretPassw0rd!"
	)

	mem := memory.New()
	bus := eventbus.NewMemory(nil)

	identityMod, err := identity.New(identity.Config{}, identity.Deps{
		Users:     mem.Users,
		EventBus:  bus,
		TxManager: mem.TxManager,
	})
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}

	tokenProvider := jwt.TokenProvider(jwt.Config{
		Secret:         strings.Repeat("x", 32),
		Issuer:         "iam-smoke",
		AccessTokenTTL: 15 * time.Minute,
	})

	authnMod, err := authn.New(authn.Config{
		JWTSecret:              strings.Repeat("x", 32),
		JWTIssuer:              "iam-smoke",
		AccessTokenTTL:         15 * time.Minute,
		SessionTTL:             24 * time.Hour,
		AllowInsecureJWTSecret: true,
	}, authn.Deps{
		Credentials:   mem.Credentials,
		Sessions:      mem.Sessions,
		Challenges:    mem.Challenges,
		EventBus:      bus,
		Identity:      identity.IntegrationFor(identityMod.Service),
		TokenProvider: tokenProvider,
		RateLimiter:   mem.RateLimiter,
	})
	if err != nil {
		t.Fatalf("authn.New: %v", err)
	}

	ctx := context.Background()

	registered, err := authnMod.Service.Register(ctx, &authn.RegisterCommand{
		AppID:    appID,
		Provider: string(authn.CredentialPassword),
		Email:    email,
		Password: password,
		TenantID: tenantID,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if registered.AccessToken == "" || registered.RefreshToken == "" {
		t.Fatalf("Register returned empty tokens: %+v", registered)
	}

	loginParams, err := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})
	if err != nil {
		t.Fatalf("marshal login params: %v", err)
	}

	loggedIn, err := authnMod.Service.Login(ctx, &authn.LoginCommand{
		AppID:     appID,
		Provider:  string(authn.CredentialPassword),
		Params:    loginParams,
		UserAgent: "smoke-test/1.0",
		IPAddress: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if loggedIn.AccessToken == "" || loggedIn.RefreshToken == "" {
		t.Fatalf("Login returned empty tokens: %+v", loggedIn)
	}

	refreshed, err := authnMod.Service.RefreshToken(ctx, &authn.RefreshTokenCommand{
		RefreshToken: loggedIn.RefreshToken,
	})
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	if refreshed.RefreshToken == loggedIn.RefreshToken {
		t.Fatalf("RefreshToken did not rotate the refresh token")
	}

	claims, err := authnMod.Service.AuthenticateToken(ctx, refreshed.AccessToken)
	if err != nil {
		t.Fatalf("AuthenticateToken: %v", err)
	}
	if claims.UserID == "" {
		t.Fatalf("AuthenticateToken returned empty user id: %+v", claims)
	}

	sessions, err := authnMod.Service.ListSessions(ctx, claims.UserID)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) == 0 {
		t.Fatalf("expected at least one active session for %s", claims.UserID)
	}
}

// TestSmoke_DuplicateRegistrationFails ensures the in-memory user
// store enforces email uniqueness within a tenant — the same
// invariant the Postgres adapter relies on the database for.
func TestSmoke_DuplicateRegistrationFails(t *testing.T) {
	const (
		appID    = "app-smoke"
		tenantID = "tenant-smoke"
		email    = "bob@example.com"
		password = "An0therS3cret!!"
	)

	mem := memory.New()
	bus := eventbus.NewMemory(nil)

	identityMod, err := identity.New(identity.Config{}, identity.Deps{
		Users:     mem.Users,
		EventBus:  bus,
		TxManager: mem.TxManager,
	})
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}

	authnMod, err := authn.New(authn.Config{
		JWTSecret:              strings.Repeat("y", 32),
		JWTIssuer:              "iam-smoke",
		AccessTokenTTL:         15 * time.Minute,
		SessionTTL:             24 * time.Hour,
		AllowInsecureJWTSecret: true,
	}, authn.Deps{
		Credentials: mem.Credentials,
		Sessions:    mem.Sessions,
		Challenges:  mem.Challenges,
		EventBus:    bus,
		Identity:    identity.IntegrationFor(identityMod.Service),
		TokenProvider: jwt.TokenProvider(jwt.Config{
			Secret:         strings.Repeat("y", 32),
			Issuer:         "iam-smoke",
			AccessTokenTTL: 15 * time.Minute,
		}),
		RateLimiter: mem.RateLimiter,
	})
	if err != nil {
		t.Fatalf("authn.New: %v", err)
	}

	ctx := context.Background()

	if _, err := authnMod.Service.Register(ctx, &authn.RegisterCommand{
		AppID:    appID,
		Provider: string(authn.CredentialPassword),
		Email:    email,
		Password: password,
		TenantID: tenantID,
	}); err != nil {
		t.Fatalf("first Register: %v", err)
	}

	_, err = authnMod.Service.Register(ctx, &authn.RegisterCommand{
		AppID:    appID,
		Provider: string(authn.CredentialPassword),
		Email:    email,
		Password: password,
		TenantID: tenantID,
	})
	if err == nil {
		t.Fatalf("second Register with same email succeeded; expected error")
	}
	if !errors.Is(err, identity.ErrEmailAlreadyTaken) {
		t.Fatalf("second Register returned %v; expected ErrEmailAlreadyTaken", err)
	}
}
