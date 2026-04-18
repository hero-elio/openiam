package rest

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"openiam/internal/identity/application"
	"openiam/internal/identity/application/command"
	"openiam/internal/identity/application/query"
)

type Handler struct {
	svc *application.IdentityService
}

func NewHandler(svc *application.IdentityService) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Post("/register", h.handleRegister)
	r.Get("/{id}", h.handleGetUser)
	r.Put("/{id}/profile", h.handleUpdateProfile)
	r.Put("/{id}/password", h.handleChangePassword)
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
	// TODO: map domain errors to HTTP status codes
	writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
}
