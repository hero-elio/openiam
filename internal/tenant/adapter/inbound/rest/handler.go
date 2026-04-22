package rest

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	// authzKeys is the canonical vocabulary for permission strings used by
	// the Checker. Importing it from the tenant REST adapter keeps the
	// route table and the seeded BuiltinPermissions in lockstep.
	authzKeys "openiam/internal/authz/domain"
	sharedAuth "openiam/internal/shared/auth"
	shared "openiam/internal/shared/domain"
	"openiam/internal/tenant/application"
	"openiam/internal/tenant/application/command"
	"openiam/internal/tenant/application/query"
	"openiam/internal/tenant/domain"
)

type Handler struct {
	svc   *application.TenantAppService
	check sharedAuth.Checker
}

func NewHandler(svc *application.TenantAppService, check sharedAuth.Checker) *Handler {
	return &Handler{svc: svc, check: check}
}

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

func (h *Handler) TenantRoutes() chi.Router {
	r := chi.NewRouter()
	r.With(h.require(authzKeys.ResourceTenants, authzKeys.ActionCreate)).Post("/", h.handleCreateTenant)
	r.With(h.require(authzKeys.ResourceTenants, authzKeys.ActionRead)).Get("/{tid}", h.handleGetTenant)
	r.With(h.require(authzKeys.ResourceApplications, authzKeys.ActionCreate)).Post("/{tid}/applications", h.handleCreateApplication)
	r.With(h.require(authzKeys.ResourceApplications, authzKeys.ActionRead)).Get("/{tid}/applications", h.handleListApplications)
	return r
}

func (h *Handler) ApplicationRoutes() chi.Router {
	r := chi.NewRouter()
	r.With(h.require(authzKeys.ResourceApplications, authzKeys.ActionRead)).Get("/{aid}", h.handleGetApplication)
	r.With(h.require(authzKeys.ResourceApplications, authzKeys.ActionUpdate)).Put("/{aid}", h.handleUpdateApplication)
	return r
}

func (h *Handler) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var req CreateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "name is required")
		return
	}

	tenantID, err := h.svc.CreateTenant(r.Context(), &command.CreateTenant{Name: req.Name})
	if err != nil {
		writeBusinessError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"id": tenantID.String()})
}

func (h *Handler) handleGetTenant(w http.ResponseWriter, r *http.Request) {
	tid := chi.URLParam(r, "tid")

	dto, err := h.svc.GetTenant(r.Context(), &query.GetTenant{TenantID: tid})
	if err != nil {
		writeBusinessError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, TenantResponse{
		ID:        dto.ID,
		Name:      dto.Name,
		Status:    dto.Status,
		CreatedAt: dto.CreatedAt,
	})
}

func (h *Handler) handleCreateApplication(w http.ResponseWriter, r *http.Request) {
	tid := chi.URLParam(r, "tid")

	claims, ok := sharedAuth.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing authentication")
		return
	}

	var req CreateApplicationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "name is required")
		return
	}

	result, err := h.svc.CreateApplication(r.Context(), &command.CreateApplication{
		TenantID:  tid,
		Name:      req.Name,
		CreatedBy: claims.UserID,
	})
	if err != nil {
		writeBusinessError(w, err)
		return
	}

	dto := result.Application
	writeJSON(w, http.StatusCreated, CreateApplicationResponse{
		ApplicationResponse: ApplicationResponse{
			ID:           dto.ID,
			TenantID:     dto.TenantID,
			Name:         dto.Name,
			ClientID:     dto.ClientID,
			RedirectURIs: dto.RedirectURIs,
			Scopes:       dto.Scopes,
			Status:       dto.Status,
			CreatedAt:    dto.CreatedAt,
		},
		ClientSecret: result.ClientSecret,
	})
}

func (h *Handler) handleListApplications(w http.ResponseWriter, r *http.Request) {
	tid := chi.URLParam(r, "tid")

	dtos, err := h.svc.ListApplications(r.Context(), &query.ListApplications{TenantID: tid})
	if err != nil {
		writeBusinessError(w, err)
		return
	}

	resp := make([]ApplicationResponse, 0, len(dtos))
	for _, dto := range dtos {
		resp = append(resp, ApplicationResponse{
			ID:           dto.ID,
			TenantID:     dto.TenantID,
			Name:         dto.Name,
			ClientID:     dto.ClientID,
			RedirectURIs: dto.RedirectURIs,
			Scopes:       dto.Scopes,
			Status:       dto.Status,
			CreatedAt:    dto.CreatedAt,
		})
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleGetApplication(w http.ResponseWriter, r *http.Request) {
	aid := chi.URLParam(r, "aid")

	dto, err := h.svc.GetApplication(r.Context(), &query.GetApplication{AppID: aid})
	if err != nil {
		writeBusinessError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, ApplicationResponse{
		ID:           dto.ID,
		TenantID:     dto.TenantID,
		Name:         dto.Name,
		ClientID:     dto.ClientID,
		RedirectURIs: dto.RedirectURIs,
		Scopes:       dto.Scopes,
		Status:       dto.Status,
		CreatedAt:    dto.CreatedAt,
	})
}

func (h *Handler) handleUpdateApplication(w http.ResponseWriter, r *http.Request) {
	aid := chi.URLParam(r, "aid")

	var req UpdateApplicationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}

	err := h.svc.UpdateApplication(r.Context(), &command.UpdateApplication{
		AppID:        aid,
		Name:         req.Name,
		RedirectURIs: req.RedirectURIs,
		Scopes:       req.Scopes,
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
	case errors.Is(err, domain.ErrTenantNotFound):
		writeError(w, http.StatusNotFound, "tenant_not_found", "tenant not found")
	case errors.Is(err, domain.ErrAppNotFound):
		writeError(w, http.StatusNotFound, "application_not_found", "application not found")
	case errors.Is(err, domain.ErrTenantAlreadyExists):
		writeError(w, http.StatusConflict, "tenant_already_exists", "tenant already exists")
	case errors.Is(err, domain.ErrAppAlreadyExists):
		writeError(w, http.StatusConflict, "application_already_exists", "application already exists")
	case errors.Is(err, domain.ErrClientIDTaken):
		writeError(w, http.StatusConflict, "client_id_taken", "client id already taken")
	case errors.Is(err, shared.ErrConcurrentUpdate):
		// Optimistic-lock conflict — caller should reload and retry.
		writeError(w, http.StatusConflict, "conflict", "resource was modified concurrently, please retry")
	case errors.Is(err, shared.ErrInvalidInput):
		writeError(w, http.StatusBadRequest, "invalid_argument", "invalid request")
	default:
		log.Printf("tenant handler: unhandled error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}
