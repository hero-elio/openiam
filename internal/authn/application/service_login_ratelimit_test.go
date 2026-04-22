package application

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"openiam/internal/authn/application/command"
	"openiam/internal/authn/domain"
	shared "openiam/internal/shared/domain"
)

type fakeLimiter struct {
	calls    []string
	blockKey string
	retry    time.Duration
	err      error
}

func (f *fakeLimiter) Allow(_ context.Context, key string, _ int, _ time.Duration) (bool, time.Duration, error) {
	f.calls = append(f.calls, key)
	if f.err != nil {
		return false, 0, f.err
	}
	if key == f.blockKey {
		return false, f.retry, nil
	}
	return true, 0, nil
}

// passwordLikeStrategy mirrors PasswordStrategy.Subject without dragging
// the credential repo into the test — we only care that the application
// layer asks the strategy for the subject and threads it into the
// limiter key.
type passwordLikeStrategy struct{}

func (passwordLikeStrategy) Type() domain.CredentialType { return domain.CredentialPassword }
func (passwordLikeStrategy) Authenticate(_ context.Context, _ *domain.AuthnRequest) (*domain.AuthnResult, error) {
	return &domain.AuthnResult{
		UserID:   shared.NewUserID(),
		TenantID: shared.NewTenantID(),
	}, nil
}
func (passwordLikeStrategy) Subject(params json.RawMessage) string {
	var p struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(p.Email))
}

// opaqueStrategy has no Subject — exercises the IP-only fallback.
type opaqueStrategy struct{}

func (opaqueStrategy) Type() domain.CredentialType { return domain.CredentialSIWE }
func (opaqueStrategy) Authenticate(_ context.Context, _ *domain.AuthnRequest) (*domain.AuthnResult, error) {
	return &domain.AuthnResult{
		UserID:   shared.NewUserID(),
		TenantID: shared.NewTenantID(),
	}, nil
}

func newLimiterTestService(strategy domain.AuthnStrategy, lim domain.RateLimiter) *AuthnAppService {
	return &AuthnAppService{
		strategies: map[domain.CredentialType]domain.AuthnStrategy{
			strategy.Type(): strategy,
		},
		sessionRepo:         &fakeSessionRepo{},
		tokenProvider:       &fakeTokenProvider{pair: &domain.TokenPair{AccessToken: "a", RefreshToken: "r"}},
		eventBus:            &fakeEventBus{},
		sessionTTL:          time.Minute,
		logger:              slog.Default(),
		loginLimiter:        lim,
		loginAttemptsBudget: DefaultLoginAttemptsPerWindow,
		loginRateWindow:     DefaultLoginRateWindow,
	}
}

func TestLogin_RateLimit_ChecksIPAndSubjectKeys(t *testing.T) {
	lim := &fakeLimiter{}
	svc := newLimiterTestService(passwordLikeStrategy{}, lim)

	params, _ := json.Marshal(map[string]string{"email": "  Alice@Example.com ", "password": "x"})
	_, err := svc.Login(context.Background(), &command.Login{
		AppID:     "app-1",
		Provider:  string(domain.CredentialPassword),
		Params:    params,
		IPAddress: "1.2.3.4",
	})
	if err != nil {
		t.Fatalf("unexpected login error: %v", err)
	}

	wantKeys := []string{
		"login:ip:1.2.3.4",
		"login:sub:app-1:password:alice@example.com",
	}
	if len(lim.calls) != len(wantKeys) {
		t.Fatalf("expected %d limiter calls, got %d (%v)", len(wantKeys), len(lim.calls), lim.calls)
	}
	for i, want := range wantKeys {
		if lim.calls[i] != want {
			t.Errorf("call[%d] = %q, want %q", i, lim.calls[i], want)
		}
	}
}

func TestLogin_RateLimit_BlockedReturnsRateLimitedError(t *testing.T) {
	lim := &fakeLimiter{
		blockKey: "login:ip:1.2.3.4",
		retry:    25 * time.Second,
	}
	svc := newLimiterTestService(passwordLikeStrategy{}, lim)

	params, _ := json.Marshal(map[string]string{"email": "alice@example.com", "password": "x"})
	_, err := svc.Login(context.Background(), &command.Login{
		AppID:     "app-1",
		Provider:  string(domain.CredentialPassword),
		Params:    params,
		IPAddress: "1.2.3.4",
	})

	var rl *domain.RateLimitedError
	if !errors.As(err, &rl) {
		t.Fatalf("expected RateLimitedError, got %v", err)
	}
	if rl.Scope != "ip" {
		t.Errorf("scope = %q, want %q", rl.Scope, "ip")
	}
	if rl.RetryAfter != 25*time.Second {
		t.Errorf("retry-after = %v, want 25s", rl.RetryAfter)
	}
}

func TestLogin_RateLimit_FailsOpenOnLimiterError(t *testing.T) {
	lim := &fakeLimiter{err: context.DeadlineExceeded}
	svc := newLimiterTestService(passwordLikeStrategy{}, lim)

	params, _ := json.Marshal(map[string]string{"email": "alice@example.com", "password": "x"})
	_, err := svc.Login(context.Background(), &command.Login{
		AppID:     "app-1",
		Provider:  string(domain.CredentialPassword),
		Params:    params,
		IPAddress: "1.2.3.4",
	})
	if err != nil {
		t.Fatalf("limiter errors should not block real users; got %v", err)
	}
}

func TestLogin_RateLimit_NoSubjectFallsBackToIPOnly(t *testing.T) {
	lim := &fakeLimiter{}
	svc := newLimiterTestService(opaqueStrategy{}, lim)

	_, err := svc.Login(context.Background(), &command.Login{
		AppID:     "app-1",
		Provider:  string(domain.CredentialSIWE),
		Params:    json.RawMessage(`{"message":"x","signature":"y"}`),
		IPAddress: "1.2.3.4",
	})
	if err != nil {
		t.Fatalf("unexpected login error: %v", err)
	}
	if len(lim.calls) != 1 || lim.calls[0] != "login:ip:1.2.3.4" {
		t.Fatalf("expected single IP-only check, got %v", lim.calls)
	}
}

func TestLogin_RateLimit_NoIPSkipsIPBucket(t *testing.T) {
	lim := &fakeLimiter{}
	svc := newLimiterTestService(passwordLikeStrategy{}, lim)

	params, _ := json.Marshal(map[string]string{"email": "alice@example.com", "password": "x"})
	_, err := svc.Login(context.Background(), &command.Login{
		AppID:    "app-1",
		Provider: string(domain.CredentialPassword),
		Params:   params,
	})
	if err != nil {
		t.Fatalf("unexpected login error: %v", err)
	}
	if len(lim.calls) != 1 || lim.calls[0] != "login:sub:app-1:password:alice@example.com" {
		t.Fatalf("expected single subject-only check when IP is unknown, got %v", lim.calls)
	}
}

func TestNoopRateLimiter_Allows(t *testing.T) {
	allowed, retry, err := domain.NoopRateLimiter{}.Allow(context.Background(), "x", 1, time.Second)
	if !allowed || retry != 0 || err != nil {
		t.Fatalf("NoopRateLimiter must always allow; got allowed=%v retry=%v err=%v", allowed, retry, err)
	}
}
