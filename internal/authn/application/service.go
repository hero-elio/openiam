package application

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"openiam/internal/authn/application/command"
	"openiam/internal/authn/application/query"
	"openiam/internal/authn/domain"
	shared "openiam/internal/shared/domain"
)

type SessionDTO struct {
	ID           string
	UserID       string
	AppID        string
	Provider     string
	UserAgent    string
	IPAddress    string
	ExpiresAt    string
	CreatedAt    string
	LastActiveAt string
}

type Option func(*AuthnAppService) error

type AuthnAppService struct {
	strategies    map[domain.CredentialType]domain.AuthnStrategy
	sessionRepo   domain.SessionRepository
	tokenProvider domain.TokenProvider
	eventBus      shared.EventBus
	registrar     domain.UserRegistrar
	sessionTTL    time.Duration
	logger        *slog.Logger
}

func NewAuthnAppService(
	sessionRepo domain.SessionRepository,
	tokenProvider domain.TokenProvider,
	eventBus shared.EventBus,
	sessionTTL time.Duration,
	logger *slog.Logger,
	opts ...Option,
) (*AuthnAppService, error) {
	if logger == nil {
		logger = slog.Default()
	}
	svc := &AuthnAppService{
		strategies:    make(map[domain.CredentialType]domain.AuthnStrategy),
		sessionRepo:   sessionRepo,
		tokenProvider: tokenProvider,
		eventBus:      eventBus,
		sessionTTL:    sessionTTL,
		logger:        logger,
	}
	for _, opt := range opts {
		if err := opt(svc); err != nil {
			return nil, fmt.Errorf("apply authn option: %w", err)
		}
	}
	if len(svc.strategies) == 0 {
		return nil, fmt.Errorf("at least one authn strategy is required")
	}
	return svc, nil
}

func (s *AuthnAppService) Login(ctx context.Context, cmd *command.Login) (*domain.TokenPair, error) {
	strategy, ok := s.strategies[domain.CredentialType(cmd.Provider)]
	if !ok {
		return nil, shared.ErrUnsupportedProvider
	}

	result, err := strategy.Authenticate(ctx, &domain.AuthnRequest{
		AppID:  shared.AppID(cmd.AppID),
		Params: cmd.Params,
	})
	if err != nil {
		return nil, err
	}

	sessionID := shared.NewSessionID()
	appID := shared.AppID(cmd.AppID)

	claims := domain.TokenClaims{
		UserID:    result.UserID.String(),
		TenantID:  result.TenantID.String(),
		AppID:     cmd.AppID,
		SessionID: sessionID.String(),
	}
	tokenPair, err := s.tokenProvider.Generate(claims)
	if err != nil {
		return nil, err
	}

	session := domain.NewSession(
		sessionID,
		result.UserID,
		result.TenantID,
		appID,
		cmd.Provider,
		tokenPair.RefreshToken,
		cmd.UserAgent,
		cmd.IPAddress,
		time.Now().Add(s.sessionTTL),
	)
	if err := s.sessionRepo.Save(ctx, session); err != nil {
		return nil, err
	}

	_ = s.eventBus.Publish(ctx, domain.UserLoggedInEvent{
		UserID:    result.UserID,
		AppID:     appID,
		Provider:  cmd.Provider,
		SessionID: sessionID,
		Timestamp: time.Now(),
	})

	s.logger.InfoContext(ctx, "user logged in",
		"user_id", result.UserID,
		"app_id", cmd.AppID,
		"provider", cmd.Provider,
		"session_id", sessionID,
	)

	return tokenPair, nil
}

func (s *AuthnAppService) BeginChallenge(ctx context.Context, cmd *command.Challenge) (*domain.ChallengeResponse, error) {
	strategy, ok := s.strategies[domain.CredentialType(cmd.Provider)]
	if !ok {
		return nil, shared.ErrUnsupportedProvider
	}

	challengeable, ok := strategy.(domain.ChallengeableStrategy)
	if !ok {
		return nil, shared.ErrChallengeNotSupported
	}

	return challengeable.Challenge(ctx, &domain.ChallengeRequest{
		AppID:  shared.AppID(cmd.AppID),
		Params: cmd.Params,
	})
}

func (s *AuthnAppService) Logout(ctx context.Context, cmd *command.Logout) error {
	sessionID := shared.SessionID(cmd.SessionID)
	userID := shared.UserID(cmd.UserID)

	if err := s.sessionRepo.Delete(ctx, sessionID); err != nil {
		return err
	}

	_ = s.eventBus.Publish(ctx, domain.UserLoggedOutEvent{
		UserID:    userID,
		SessionID: sessionID,
		Timestamp: time.Now(),
	})

	s.logger.InfoContext(ctx, "user logged out",
		"user_id", userID,
		"session_id", sessionID,
	)

	return nil
}

func (s *AuthnAppService) RefreshToken(ctx context.Context, cmd *command.RefreshToken) (*domain.TokenPair, error) {
	session, err := s.sessionRepo.FindByRefreshToken(ctx, cmd.RefreshToken)
	if err != nil {
		return nil, err
	}

	if session.IsExpired() {
		_ = s.sessionRepo.Delete(ctx, session.ID)
		return nil, shared.ErrSessionExpired
	}

	claims := domain.TokenClaims{
		UserID:    session.UserID.String(),
		TenantID:  session.TenantID.String(),
		AppID:     session.AppID.String(),
		SessionID: session.ID.String(),
	}
	tokenPair, err := s.tokenProvider.Generate(claims)
	if err != nil {
		return nil, err
	}

	session.Refresh(tokenPair.RefreshToken, time.Now().Add(s.sessionTTL))
	if err := s.sessionRepo.Update(ctx, session); err != nil {
		return nil, err
	}

	_ = s.eventBus.Publish(ctx, domain.TokenRefreshedEvent{
		UserID:    session.UserID,
		SessionID: session.ID,
		Timestamp: time.Now(),
	})

	return tokenPair, nil
}

func (s *AuthnAppService) GetSession(ctx context.Context, q *query.GetSession) (*SessionDTO, error) {
	session, err := s.sessionRepo.FindByID(ctx, shared.SessionID(q.SessionID))
	if err != nil {
		return nil, err
	}
	return toSessionDTO(session), nil
}

func (s *AuthnAppService) ListSessions(ctx context.Context, userID string) ([]*SessionDTO, error) {
	sessions, err := s.sessionRepo.ListByUser(ctx, shared.UserID(userID))
	if err != nil {
		return nil, err
	}
	result := make([]*SessionDTO, len(sessions))
	for i, sess := range sessions {
		result[i] = toSessionDTO(sess)
	}
	return result, nil
}

func (s *AuthnAppService) BindCredential(ctx context.Context, cmd *command.BindCredential) error {
	strategy, ok := s.strategies[domain.CredentialType(cmd.Provider)]
	if !ok {
		return shared.ErrUnsupportedProvider
	}

	bindable, ok := strategy.(domain.BindableStrategy)
	if !ok {
		return fmt.Errorf("provider %q does not support credential binding", cmd.Provider)
	}

	return bindable.VerifyAndBind(ctx, &domain.AuthnRequest{
		AppID:  shared.AppID(cmd.AppID),
		Params: cmd.Params,
	}, shared.UserID(cmd.UserID))
}

func (s *AuthnAppService) Register(ctx context.Context, cmd *command.Register) (*domain.TokenPair, error) {
	if s.registrar == nil {
		return nil, fmt.Errorf("user registrar not configured")
	}

	provider := cmd.Provider
	if provider == "" {
		provider = "password"
	}

	_, err := s.registrar.Register(ctx, &domain.RegisterRequest{
		AppID:    cmd.AppID,
		Provider: provider,
		Email:    cmd.Email,
		Password: cmd.Password,
		TenantID: cmd.TenantID,
	})
	if err != nil {
		return nil, err
	}

	params, _ := json.Marshal(map[string]string{
		"email":    cmd.Email,
		"password": cmd.Password,
	})

	return s.Login(ctx, &command.Login{
		AppID:    cmd.AppID,
		Provider: provider,
		Params:   params,
	})
}

func toSessionDTO(s *domain.Session) *SessionDTO {
	return &SessionDTO{
		ID:           s.ID.String(),
		UserID:       s.UserID.String(),
		AppID:        s.AppID.String(),
		Provider:     s.Provider,
		UserAgent:    s.UserAgent,
		IPAddress:    s.IPAddress,
		ExpiresAt:    s.ExpiresAt.Format(time.RFC3339),
		CreatedAt:    s.CreatedAt.Format(time.RFC3339),
		LastActiveAt: s.LastActiveAt.Format(time.RFC3339),
	}
}
