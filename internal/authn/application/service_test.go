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
	"openiam/internal/authn/application/query"
	"openiam/internal/authn/domain"
	shared "openiam/internal/shared/domain"
)

type fakeAuthnStrategy struct {
	result *domain.AuthnResult
	err    error
}

func (f *fakeAuthnStrategy) Type() domain.CredentialType { return domain.CredentialPassword }

func (f *fakeAuthnStrategy) Authenticate(context.Context, *domain.AuthnRequest) (*domain.AuthnResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

type fakeSessionRepo struct {
	saved      *domain.Session
	found      *domain.Session
	foundByID  *domain.Session
	list       []*domain.Session
	findErr    error
	updated    *domain.Session
	deletedID  shared.SessionID
	deletedCnt int
	deleteErr  error
}

func (f *fakeSessionRepo) Save(_ context.Context, session *domain.Session) error {
	f.saved = session
	return nil
}

func (f *fakeSessionRepo) FindByID(_ context.Context, id shared.SessionID) (*domain.Session, error) {
	if f.foundByID != nil && f.foundByID.ID == id {
		return f.foundByID, nil
	}
	return nil, shared.ErrNotFound
}

func (f *fakeSessionRepo) FindByRefreshToken(context.Context, string) (*domain.Session, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	if f.found != nil {
		return f.found, nil
	}
	return nil, shared.ErrNotFound
}

func (f *fakeSessionRepo) Update(_ context.Context, session *domain.Session) error {
	f.updated = session
	return nil
}

func (f *fakeSessionRepo) Delete(_ context.Context, id shared.SessionID) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deletedID = id
	f.deletedCnt++
	return nil
}

func (f *fakeSessionRepo) DeleteByUser(context.Context, shared.UserID) error { return nil }

func (f *fakeSessionRepo) ListByUser(context.Context, shared.UserID) ([]*domain.Session, error) {
	return f.list, nil
}

type fakeTokenProvider struct {
	pair *domain.TokenPair
	err  error
}

func (f *fakeTokenProvider) Generate(domain.TokenClaims) (*domain.TokenPair, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.pair, nil
}

func (f *fakeTokenProvider) Validate(string) (*domain.TokenClaims, error) { return nil, nil }

type fakeEventBus struct {
	published []shared.DomainEvent
}

func (f *fakeEventBus) Publish(_ context.Context, events ...shared.DomainEvent) error {
	f.published = append(f.published, events...)
	return nil
}

func (f *fakeEventBus) Subscribe(string, shared.EventHandler) error { return nil }

type fakeChallengeStrategy struct {
	result *domain.AuthnResult
	resp   *domain.ChallengeResponse
}

func (f *fakeChallengeStrategy) Type() domain.CredentialType { return domain.CredentialWebAuthn }

func (f *fakeChallengeStrategy) Authenticate(context.Context, *domain.AuthnRequest) (*domain.AuthnResult, error) {
	return f.result, nil
}

func (f *fakeChallengeStrategy) Challenge(context.Context, *domain.ChallengeRequest) (*domain.ChallengeResponse, error) {
	return f.resp, nil
}

type fakeBindableStrategy struct {
	result       *domain.AuthnResult
	capturedUser shared.UserID
	capturedApp  shared.AppID
}

func (f *fakeBindableStrategy) Type() domain.CredentialType { return domain.CredentialWebAuthn }

func (f *fakeBindableStrategy) Authenticate(context.Context, *domain.AuthnRequest) (*domain.AuthnResult, error) {
	return f.result, nil
}

func (f *fakeBindableStrategy) VerifyAndBind(_ context.Context, req *domain.AuthnRequest, userID shared.UserID) error {
	f.capturedUser = userID
	f.capturedApp = req.AppID
	return nil
}

type fakeRegistrar struct {
	captured *domain.RegisterRequest
}

func (f *fakeRegistrar) Register(_ context.Context, req *domain.RegisterRequest) (string, error) {
	f.captured = req
	return "user-1", nil
}

func TestAuthnAppService_LoginUnsupportedProvider(t *testing.T) {
	svc := &AuthnAppService{
		strategies:    map[domain.CredentialType]domain.AuthnStrategy{},
		sessionRepo:   &fakeSessionRepo{},
		tokenProvider: &fakeTokenProvider{pair: &domain.TokenPair{}},
		eventBus:      &fakeEventBus{},
		sessionTTL:    15 * time.Minute,
		logger:        slog.Default(),
	}

	_, err := svc.Login(context.Background(), &command.Login{
		AppID:    shared.NewAppID().String(),
		Provider: "unknown",
	})
	if err != domain.ErrUnsupportedProvider {
		t.Fatalf("unexpected error: got %v want %v", err, domain.ErrUnsupportedProvider)
	}
}

func TestAuthnAppService_LoginSuccessSavesSessionAndPublishesEvent(t *testing.T) {
	sessionRepo := &fakeSessionRepo{}
	bus := &fakeEventBus{}
	userID := shared.NewUserID()
	tenantID := shared.NewTenantID()
	strategy := &fakeAuthnStrategy{
		result: &domain.AuthnResult{
			UserID:   userID,
			TenantID: tenantID,
		},
	}
	svc := &AuthnAppService{
		strategies: map[domain.CredentialType]domain.AuthnStrategy{
			domain.CredentialPassword: strategy,
		},
		sessionRepo:   sessionRepo,
		tokenProvider: &fakeTokenProvider{pair: &domain.TokenPair{AccessToken: "a", RefreshToken: "r"}},
		eventBus:      bus,
		sessionTTL:    15 * time.Minute,
		logger:        slog.Default(),
	}

	params, _ := json.Marshal(map[string]string{"email": "alice@example.com", "password": "password123"})
	tokenPair, err := svc.Login(context.Background(), &command.Login{
		AppID:     shared.NewAppID().String(),
		Provider:  string(domain.CredentialPassword),
		Params:    params,
		UserAgent: "test-agent",
		IPAddress: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokenPair == nil || tokenPair.RefreshToken != "r" {
		t.Fatalf("token pair mismatch")
	}
	if sessionRepo.saved == nil {
		t.Fatal("session should be saved")
	}
	if sessionRepo.saved.UserID != userID || sessionRepo.saved.TenantID != tenantID {
		t.Fatalf("saved session principal mismatch")
	}
	if len(bus.published) != 1 {
		t.Fatalf("expected one login event, got %d", len(bus.published))
	}
}

func TestAuthnAppService_RefreshToken_ExpiredSession(t *testing.T) {
	expired := domain.NewSession(
		shared.NewSessionID(),
		shared.NewUserID(),
		shared.NewTenantID(),
		shared.NewAppID(),
		"password",
		"old-r",
		"ua",
		"127.0.0.1",
		time.Now().Add(-time.Minute),
	)
	sessionRepo := &fakeSessionRepo{found: expired}
	svc := &AuthnAppService{
		strategies:    map[domain.CredentialType]domain.AuthnStrategy{domain.CredentialPassword: &fakeAuthnStrategy{}},
		sessionRepo:   sessionRepo,
		tokenProvider: &fakeTokenProvider{pair: &domain.TokenPair{}},
		eventBus:      &fakeEventBus{},
		sessionTTL:    15 * time.Minute,
		logger:        slog.Default(),
	}

	_, err := svc.RefreshToken(context.Background(), &command.RefreshToken{RefreshToken: "old-r"})
	if err != domain.ErrSessionExpired {
		t.Fatalf("unexpected error: got %v want %v", err, domain.ErrSessionExpired)
	}
	if sessionRepo.deletedCnt != 1 || sessionRepo.deletedID != expired.ID {
		t.Fatalf("expired session should be deleted")
	}
}

func TestAuthnAppService_BeginChallenge(t *testing.T) {
	svc := &AuthnAppService{
		strategies: map[domain.CredentialType]domain.AuthnStrategy{
			domain.CredentialPassword: &fakeAuthnStrategy{},
			domain.CredentialWebAuthn: &fakeChallengeStrategy{
				resp: &domain.ChallengeResponse{ChallengeID: "c1", Provider: "webauthn"},
			},
		},
		sessionRepo:   &fakeSessionRepo{},
		tokenProvider: &fakeTokenProvider{pair: &domain.TokenPair{}},
		eventBus:      &fakeEventBus{},
		sessionTTL:    15 * time.Minute,
		logger:        slog.Default(),
	}

	_, err := svc.BeginChallenge(context.Background(), &command.Challenge{
		AppID:    shared.NewAppID().String(),
		Provider: "password",
	})
	if err != domain.ErrChallengeNotSupported {
		t.Fatalf("unexpected error: got %v want %v", err, domain.ErrChallengeNotSupported)
	}

	resp, err := svc.BeginChallenge(context.Background(), &command.Challenge{
		AppID:    shared.NewAppID().String(),
		Provider: "webauthn",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.ChallengeID != "c1" {
		t.Fatalf("challenge response mismatch")
	}
}

func TestAuthnAppService_BindCredential(t *testing.T) {
	bindable := &fakeBindableStrategy{}
	svc := &AuthnAppService{
		strategies: map[domain.CredentialType]domain.AuthnStrategy{
			domain.CredentialPassword: &fakeAuthnStrategy{},
			domain.CredentialWebAuthn: bindable,
		},
		sessionRepo:   &fakeSessionRepo{},
		tokenProvider: &fakeTokenProvider{pair: &domain.TokenPair{}},
		eventBus:      &fakeEventBus{},
		sessionTTL:    15 * time.Minute,
		logger:        slog.Default(),
	}

	err := svc.BindCredential(context.Background(), &command.BindCredential{
		UserID:   shared.NewUserID().String(),
		AppID:    shared.NewAppID().String(),
		Provider: "password",
	})
	if err == nil || !strings.Contains(err.Error(), "does not support credential binding") {
		t.Fatalf("expected non-bindable provider error, got %v", err)
	}

	userID := shared.NewUserID()
	appID := shared.NewAppID()
	err = svc.BindCredential(context.Background(), &command.BindCredential{
		UserID:   userID.String(),
		AppID:    appID.String(),
		Provider: "webauthn",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bindable.capturedUser != userID || bindable.capturedApp != appID {
		t.Fatalf("bindable strategy received wrong context")
	}
}

func TestAuthnAppService_RegisterRequiresRegistrar(t *testing.T) {
	svc := &AuthnAppService{
		strategies:    map[domain.CredentialType]domain.AuthnStrategy{domain.CredentialPassword: &fakeAuthnStrategy{}},
		sessionRepo:   &fakeSessionRepo{},
		tokenProvider: &fakeTokenProvider{pair: &domain.TokenPair{}},
		eventBus:      &fakeEventBus{},
		sessionTTL:    15 * time.Minute,
		logger:        slog.Default(),
	}

	_, err := svc.Register(context.Background(), &command.Register{})
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("expected missing registrar error, got %v", err)
	}
}

func TestAuthnAppService_RegisterDefaultsProviderAndLogin(t *testing.T) {
	registrar := &fakeRegistrar{}
	userID := shared.NewUserID()
	tenantID := shared.NewTenantID()
	svc := &AuthnAppService{
		strategies: map[domain.CredentialType]domain.AuthnStrategy{
			domain.CredentialPassword: &fakeAuthnStrategy{
				result: &domain.AuthnResult{UserID: userID, TenantID: tenantID},
			},
		},
		sessionRepo:   &fakeSessionRepo{},
		tokenProvider: &fakeTokenProvider{pair: &domain.TokenPair{AccessToken: "a", RefreshToken: "r"}},
		eventBus:      &fakeEventBus{},
		registrar:     registrar,
		sessionTTL:    15 * time.Minute,
		logger:        slog.Default(),
	}

	tenant := shared.NewTenantID().String()
	app := shared.NewAppID().String()
	pair, err := svc.Register(context.Background(), &command.Register{
		AppID:    app,
		Email:    "alice@example.com",
		Password: "password123",
		TenantID: tenant,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pair == nil || pair.RefreshToken != "r" {
		t.Fatalf("token pair mismatch")
	}
	if registrar.captured == nil {
		t.Fatal("registrar should be called")
	}
	if registrar.captured.Provider != "password" {
		t.Fatalf("expected default provider password, got %q", registrar.captured.Provider)
	}
}

func TestAuthnAppService_RefreshToken_RepoErrorPassthrough(t *testing.T) {
	repoErr := errors.New("repo unavailable")
	svc := &AuthnAppService{
		strategies:    map[domain.CredentialType]domain.AuthnStrategy{domain.CredentialPassword: &fakeAuthnStrategy{}},
		sessionRepo:   &fakeSessionRepo{findErr: repoErr},
		tokenProvider: &fakeTokenProvider{pair: &domain.TokenPair{}},
		eventBus:      &fakeEventBus{},
		sessionTTL:    15 * time.Minute,
		logger:        slog.Default(),
	}

	_, err := svc.RefreshToken(context.Background(), &command.RefreshToken{RefreshToken: "r"})
	if !errors.Is(err, repoErr) {
		t.Fatalf("expected repo error passthrough, got %v", err)
	}
}

func TestAuthnAppService_RefreshToken_Success(t *testing.T) {
	session := domain.NewSession(
		shared.NewSessionID(),
		shared.NewUserID(),
		shared.NewTenantID(),
		shared.NewAppID(),
		"password",
		"old-r",
		"ua",
		"127.0.0.1",
		time.Now().Add(10*time.Minute),
	)
	repo := &fakeSessionRepo{found: session}
	bus := &fakeEventBus{}
	svc := &AuthnAppService{
		strategies:    map[domain.CredentialType]domain.AuthnStrategy{domain.CredentialPassword: &fakeAuthnStrategy{}},
		sessionRepo:   repo,
		tokenProvider: &fakeTokenProvider{pair: &domain.TokenPair{AccessToken: "new-a", RefreshToken: "new-r"}},
		eventBus:      bus,
		sessionTTL:    15 * time.Minute,
		logger:        slog.Default(),
	}

	pair, err := svc.RefreshToken(context.Background(), &command.RefreshToken{RefreshToken: "old-r"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pair == nil || pair.RefreshToken != "new-r" {
		t.Fatalf("token refresh result mismatch")
	}
	if repo.updated == nil {
		t.Fatal("session should be updated")
	}
	if repo.updated.RefreshToken != "new-r" {
		t.Fatalf("session refresh token should be rotated")
	}
	if len(bus.published) != 1 {
		t.Fatalf("expected one token refreshed event, got %d", len(bus.published))
	}
}

func TestAuthnAppService_LogoutAndGetSessionAndList(t *testing.T) {
	userID := shared.NewUserID()
	session := domain.NewSession(
		shared.NewSessionID(),
		userID,
		shared.NewTenantID(),
		shared.NewAppID(),
		"password",
		"r",
		"ua",
		"127.0.0.1",
		time.Now().Add(10*time.Minute),
	)
	repo := &fakeSessionRepo{
		foundByID: session,
		list:      []*domain.Session{session},
	}
	bus := &fakeEventBus{}
	svc := &AuthnAppService{
		strategies:    map[domain.CredentialType]domain.AuthnStrategy{domain.CredentialPassword: &fakeAuthnStrategy{}},
		sessionRepo:   repo,
		tokenProvider: &fakeTokenProvider{pair: &domain.TokenPair{}},
		eventBus:      bus,
		sessionTTL:    15 * time.Minute,
		logger:        slog.Default(),
	}

	if err := svc.Logout(context.Background(), &command.Logout{
		SessionID: session.ID.String(),
		UserID:    userID.String(),
	}); err != nil {
		t.Fatalf("unexpected logout error: %v", err)
	}
	if repo.deletedCnt != 1 || repo.deletedID != session.ID {
		t.Fatalf("logout should delete target session")
	}
	if len(bus.published) != 1 {
		t.Fatalf("expected one logout event, got %d", len(bus.published))
	}

	dto, err := svc.GetSession(context.Background(), &query.GetSession{SessionID: session.ID.String()})
	if err != nil {
		t.Fatalf("unexpected get session error: %v", err)
	}
	if dto == nil || dto.ID != session.ID.String() || dto.UserID != userID.String() {
		t.Fatalf("session dto mismatch")
	}

	list, err := svc.ListSessions(context.Background(), userID.String())
	if err != nil {
		t.Fatalf("unexpected list sessions error: %v", err)
	}
	if len(list) != 1 || list[0].ID != session.ID.String() {
		t.Fatalf("list sessions mismatch")
	}
}

func TestAuthnAppService_Login_TokenGenerateError(t *testing.T) {
	strategy := &fakeAuthnStrategy{
		result: &domain.AuthnResult{
			UserID:   shared.NewUserID(),
			TenantID: shared.NewTenantID(),
		},
	}
	tokenErr := errors.New("token generate failed")
	svc := &AuthnAppService{
		strategies: map[domain.CredentialType]domain.AuthnStrategy{
			domain.CredentialPassword: strategy,
		},
		sessionRepo:   &fakeSessionRepo{},
		tokenProvider: &fakeTokenProvider{err: tokenErr},
		eventBus:      &fakeEventBus{},
		sessionTTL:    15 * time.Minute,
		logger:        slog.Default(),
	}

	_, err := svc.Login(context.Background(), &command.Login{
		AppID:    shared.NewAppID().String(),
		Provider: string(domain.CredentialPassword),
	})
	if !errors.Is(err, tokenErr) {
		t.Fatalf("expected token provider error passthrough, got %v", err)
	}
}

func TestAuthnAppService_Logout_DeleteError(t *testing.T) {
	deleteErr := errors.New("delete failed")
	svc := &AuthnAppService{
		strategies:    map[domain.CredentialType]domain.AuthnStrategy{domain.CredentialPassword: &fakeAuthnStrategy{}},
		sessionRepo:   &fakeSessionRepo{deleteErr: deleteErr},
		tokenProvider: &fakeTokenProvider{pair: &domain.TokenPair{}},
		eventBus:      &fakeEventBus{},
		sessionTTL:    15 * time.Minute,
		logger:        slog.Default(),
	}

	err := svc.Logout(context.Background(), &command.Logout{
		SessionID: shared.NewSessionID().String(),
		UserID:    shared.NewUserID().String(),
	})
	if !errors.Is(err, deleteErr) {
		t.Fatalf("expected delete error passthrough, got %v", err)
	}
}
