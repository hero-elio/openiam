package rest

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	shared "openiam/internal/shared/domain"

	"openiam/internal/authz/application"
	"openiam/internal/authz/application/command"
	"openiam/internal/authz/application/query"
)

type Handler struct {
	svc *application.AuthzAppService
}

func NewHandler(svc *application.AuthzAppService) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Post("/roles", h.handleCreateRole)
	r.Get("/roles", h.handleListRoles)
	r.Post("/roles/{id}/permissions", h.handleGrantPermission)
	r.Delete("/roles/{id}/permissions", h.handleRevokePermission)
	r.Post("/users/{uid}/roles", h.handleAssignRole)
	r.Delete("/users/{uid}/roles/{rid}", h.handleUnassignRole)
	r.Post("/check", h.handleCheckPermission)
	return r
}

func (h *Handler) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	var req CreateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}

	if req.Name == "" || req.AppID == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "name and app_id are required")
		return
	}

	roleID, err := h.svc.CreateRole(r.Context(), &command.CreateRole{
		AppID:       req.AppID,
		TenantID:    req.TenantID,
		Name:        req.Name,
		Description: req.Description,
	})
	if err != nil {
		writeBusinessError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"id": roleID.String()})
}

func (h *Handler) handleListRoles(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "app_id query parameter is required")
		return
	}

	roles, err := h.svc.ListRoles(r.Context(), &query.ListRoles{AppID: appID})
	if err != nil {
		writeBusinessError(w, err)
		return
	}

	resp := make([]RoleResponse, 0, len(roles))
	for _, dto := range roles {
		resp = append(resp, RoleResponse{
			ID:          dto.ID,
			AppID:       dto.AppID,
			TenantID:    dto.TenantID,
			Name:        dto.Name,
			Description: dto.Description,
			Permissions: dto.Permissions,
			IsSystem:    dto.IsSystem,
			CreatedAt:   dto.CreatedAt,
		})
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleGrantPermission(w http.ResponseWriter, r *http.Request) {
	roleID := chi.URLParam(r, "id")

	var req GrantPermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}

	if req.Resource == "" || req.Action == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "resource and action are required")
		return
	}

	err := h.svc.GrantPermission(r.Context(), &command.GrantPermission{
		RoleID:   roleID,
		Resource: req.Resource,
		Action:   req.Action,
	})
	if err != nil {
		writeBusinessError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleRevokePermission(w http.ResponseWriter, r *http.Request) {
	roleID := chi.URLParam(r, "id")

	var req RevokePermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}

	err := h.svc.RevokePermission(r.Context(), &command.RevokePermission{
		RoleID:   roleID,
		Resource: req.Resource,
		Action:   req.Action,
	})
	if err != nil {
		writeBusinessError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleAssignRole(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "uid")

	var req AssignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}

	if req.RoleID == "" || req.AppID == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "role_id and app_id are required")
		return
	}

	err := h.svc.AssignRole(r.Context(), &command.AssignRole{
		UserID:   userID,
		AppID:    req.AppID,
		RoleID:   req.RoleID,
		TenantID: req.TenantID,
	})
	if err != nil {
		writeBusinessError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleUnassignRole(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "uid")
	roleID := chi.URLParam(r, "rid")
	appID := r.URL.Query().Get("app_id")

	if appID == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "app_id query parameter is required")
		return
	}

	err := h.svc.UnassignRole(r.Context(), userID, appID, roleID)
	if err != nil {
		writeBusinessError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleCheckPermission(w http.ResponseWriter, r *http.Request) {
	var req CheckPermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}

	if req.UserID == "" || req.AppID == "" || req.Resource == "" || req.Action == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "user_id, app_id, resource, and action are required")
		return
	}

	result, err := h.svc.CheckPermission(r.Context(), &query.CheckPermission{
		UserID:   req.UserID,
		AppID:    req.AppID,
		Resource: req.Resource,
		Action:   req.Action,
	})
	if err != nil {
		writeBusinessError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, CheckPermissionResponse{Allowed: result.Allowed})
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
	case errors.Is(err, shared.ErrRoleNotFound):
		writeError(w, http.StatusNotFound, "role_not_found", err.Error())
	case errors.Is(err, shared.ErrRoleAlreadyExists):
		writeError(w, http.StatusConflict, "role_already_exists", err.Error())
	case errors.Is(err, shared.ErrPermissionAlreadyGranted):
		writeError(w, http.StatusConflict, "permission_already_granted", err.Error())
	case errors.Is(err, shared.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
	}
}
