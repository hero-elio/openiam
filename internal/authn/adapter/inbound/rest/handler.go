package rest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"openiam/internal/authn/application"
	"openiam/internal/authn/application/command"
	"openiam/internal/authn/domain"
	shared "openiam/internal/shared/domain"
)

type contextKey string

const (
	ctxUserID    contextKey = "user_id"
	ctxSessionID contextKey = "session_id"
	ctxTenantID  contextKey = "tenant_id"
	ctxAppID     contextKey = "app_id"
)

type Handler struct {
	svc           *application.AuthnAppService
	tokenProvider domain.TokenProvider
}

func NewHandler(svc *application.AuthnAppService, tokenProvider domain.TokenProvider) *Handler {
	return &Handler{svc: svc, tokenProvider: tokenProvider}
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Post("/register", h.handleRegister)
	r.Post("/login", h.handleLogin)
	r.Post("/token/refresh", h.handleRefreshToken)

	r.Group(func(r chi.Router) {
		r.Use(h.AuthMiddleware)
		r.Post("/logout", h.handleLogout)
		r.Get("/sessions", h.handleListSessions)
		r.Delete("/sessions/{id}", h.handleRevokeSession)
	})

	return r
}

func (h *Handler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := extractBearerToken(r)
		if raw == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
			return
		}
		claims, err := h.tokenProvider.Validate(raw)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", "invalid token")
			return
		}
		ctx := context.WithValue(r.Context(), ctxUserID, claims.UserID)
		ctx = context.WithValue(ctx, ctxSessionID, claims.SessionID)
		ctx = context.WithValue(ctx, ctxTenantID, claims.TenantID)
		ctx = context.WithValue(ctx, ctxAppID, claims.AppID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}

	if req.AppID == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "app_id is required")
		return
	}
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "email and password are required")
		return
	}

	tokenPair, err := h.svc.Register(r.Context(), &command.Register{
		AppID:    req.AppID,
		Provider: req.Provider,
		Email:    req.Email,
		Password: req.Password,
		TenantID: req.TenantID,
	})
	if err != nil {
		writeBusinessError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, TokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		TokenType:    tokenPair.TokenType,
		ExpiresIn:    tokenPair.ExpiresIn,
	})
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}

	if req.AppID == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "app_id is required")
		return
	}

	provider := req.Provider
	if provider == "" {
		provider = "password"
	}

	params := map[string]string{
		"email":    req.Email,
		"password": req.Password,
	}

	tokenPair, err := h.svc.Login(r.Context(), &command.Login{
		AppID:     req.AppID,
		Provider:  provider,
		Params:    params,
		UserAgent: r.UserAgent(),
		IPAddress: realIP(r),
	})
	if err != nil {
		writeBusinessError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, TokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		TokenType:    tokenPair.TokenType,
		ExpiresIn:    tokenPair.ExpiresIn,
	})
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(ctxUserID).(string)
	sessionID, _ := r.Context().Value(ctxSessionID).(string)

	if err := h.svc.Logout(r.Context(), &command.Logout{
		SessionID: sessionID,
		UserID:    userID,
	}); err != nil {
		writeBusinessError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	var req RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}

	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "refresh_token is required")
		return
	}

	tokenPair, err := h.svc.RefreshToken(r.Context(), &command.RefreshToken{
		RefreshToken: req.RefreshToken,
		UserAgent:    r.UserAgent(),
		IPAddress:    realIP(r),
	})
	if err != nil {
		writeBusinessError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, TokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		TokenType:    tokenPair.TokenType,
		ExpiresIn:    tokenPair.ExpiresIn,
	})
}

func (h *Handler) handleListSessions(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(ctxUserID).(string)

	sessions, err := h.svc.ListSessions(r.Context(), userID)
	if err != nil {
		writeBusinessError(w, err)
		return
	}

	resp := make([]SessionResponse, len(sessions))
	for i, s := range sessions {
		resp[i] = SessionResponse{
			ID:           s.ID,
			UserID:       s.UserID,
			AppID:        s.AppID,
			Provider:     s.Provider,
			UserAgent:    s.UserAgent,
			IPAddress:    s.IPAddress,
			ExpiresAt:    s.ExpiresAt,
			CreatedAt:    s.CreatedAt,
			LastActiveAt: s.LastActiveAt,
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value(ctxUserID).(string)
	sessionID := chi.URLParam(r, "id")

	if err := h.svc.Logout(r.Context(), &command.Logout{
		SessionID: sessionID,
		UserID:    userID,
	}); err != nil {
		writeBusinessError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, ErrorResponse{Code: code, Message: message})
}

func writeBusinessError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrInvalidCredential), errors.Is(err, shared.ErrInvalidPassword):
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
	case errors.Is(err, shared.ErrUserNotFound), errors.Is(err, shared.ErrCredentialNotFound):
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
	case errors.Is(err, shared.ErrEmailAlreadyTaken):
		writeError(w, http.StatusConflict, "email_taken", "email is already registered")
	case errors.Is(err, shared.ErrPasswordTooShort):
		writeError(w, http.StatusBadRequest, "password_too_short", "password must be at least 8 characters")
	case errors.Is(err, shared.ErrUserDisabled):
		writeError(w, http.StatusForbidden, "user_disabled", "account is disabled")
	case errors.Is(err, shared.ErrUserLocked):
		writeError(w, http.StatusForbidden, "user_locked", "account is locked")
	case errors.Is(err, shared.ErrSessionNotFound):
		writeError(w, http.StatusUnauthorized, "session_not_found", "session not found")
	case errors.Is(err, shared.ErrSessionExpired):
		writeError(w, http.StatusUnauthorized, "session_expired", "session has expired")
	case errors.Is(err, shared.ErrUnsupportedProvider):
		writeError(w, http.StatusBadRequest, "unsupported_provider", "unsupported authentication provider")
	case errors.Is(err, shared.ErrInvalidToken), errors.Is(err, shared.ErrTokenExpired):
		writeError(w, http.StatusUnauthorized, "invalid_token", "token is invalid or expired")
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", "an internal error occurred")
	}
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

func realIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return xff
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return r.RemoteAddr
}
