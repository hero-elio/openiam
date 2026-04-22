package rest

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	sharedAuth "openiam/internal/shared/auth"
	"openiam/internal/identity/application"
	"openiam/internal/identity/application/command"
	"openiam/internal/identity/application/query"
	"openiam/internal/identity/domain"
	shared "openiam/internal/shared/domain"
)

type Handler struct {
	svc   *application.IdentityService
	check sharedAuth.Checker
}

func NewHandler(svc *application.IdentityService, check sharedAuth.Checker) *Handler {
	return &Handler{svc: svc, check: check}
}

// require wraps the protocol-agnostic Checker as chi middleware.
func (h *Handler) require(resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := h.check(r.Context(), resource, action); err != nil {
				writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// requireOwnerOr allows the request if the caller is the resource owner (URL
// param "id" matches Claims.UserID), otherwise falls back to a permission check.
func (h *Handler) requireOwnerOr(resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := sharedAuth.ClaimsFromContext(r.Context())
			if !ok {
				writeError(w, http.StatusUnauthorized, "unauthorized", "missing authentication")
				return
			}
			targetUID := chi.URLParam(r, "id")
			if targetUID == claims.UserID {
				next.ServeHTTP(w, r)
				return
			}
			if err := h.check(r.Context(), resource, action); err != nil {
				writeError(w, http.StatusForbidden, "forbidden", "insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Post("/register", h.handleRegister)
	r.With(h.requireOwnerOr("users", "read")).Get("/{id}", h.handleGetUser)
	r.With(h.requireOwnerOr("users", "update")).Put("/{id}/profile", h.handleUpdateProfile)
	r.With(h.requireOwnerOr("users", "update")).Put("/{id}/password", h.handleChangePassword)
	return r
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "email and password are required")
		return
	}

	if req.AppID == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "app_id is required")
		return
	}

	userID, err := h.svc.RegisterUser(r.Context(), &command.RegisterUser{
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

	writeJSON(w, http.StatusCreated, map[string]string{"id": userID.String()})
}

func (h *Handler) handleGetUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")

	dto, err := h.svc.GetUser(r.Context(), &query.GetUser{UserID: userID})
	if err != nil {
		writeBusinessError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, UserResponse{
		ID:          dto.ID,
		Email:       dto.Email,
		DisplayName: dto.DisplayName,
		AvatarURL:   dto.AvatarURL,
		Status:      dto.Status,
		TenantID:    dto.TenantID,
		CreatedAt:   dto.CreatedAt,
	})
}

func (h *Handler) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")

	var req UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}

	err := h.svc.UpdateProfile(r.Context(), &command.UpdateProfile{
		UserID:      userID,
		DisplayName: req.DisplayName,
		AvatarURL:   req.AvatarURL,
	})
	if err != nil {
		writeBusinessError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}

	err := h.svc.ChangePassword(r.Context(), &command.ChangePassword{
		UserID:      userID,
		OldPassword: req.OldPassword,
		NewPassword: req.NewPassword,
	})
	if err != nil {
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
	case errors.Is(err, domain.ErrUserNotFound):
		writeError(w, http.StatusNotFound, "user_not_found", "user not found")
	case errors.Is(err, domain.ErrUserAlreadyExists),
		errors.Is(err, domain.ErrEmailAlreadyTaken):
		writeError(w, http.StatusConflict, "user_already_exists", "user already exists")
	case errors.Is(err, domain.ErrInvalidEmail),
		errors.Is(err, domain.ErrPasswordTooShort):
		writeError(w, http.StatusBadRequest, "invalid_input", "invalid input")
	case errors.Is(err, domain.ErrInvalidPassword):
		writeError(w, http.StatusUnauthorized, "invalid_password", "invalid password")
	case errors.Is(err, shared.ErrConcurrentUpdate):
		writeError(w, http.StatusConflict, "conflict", "user was modified concurrently, please retry")
	default:
		log.Printf("identity handler: unhandled error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}
