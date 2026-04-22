package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"openiam/pkg/iam/authz"
)

type fakeAuthzService struct {
	authz.Service

	listRoleMembersFn func(ctx context.Context, q *authz.ListRoleMembersQuery) ([]*authz.UserAppRoleDTO, error)
}

func (f *fakeAuthzService) ListRoleMembers(ctx context.Context, q *authz.ListRoleMembersQuery) ([]*authz.UserAppRoleDTO, error) {
	if f.listRoleMembersFn == nil {
		return nil, nil
	}
	return f.listRoleMembersFn(ctx, q)
}

func TestMountAuthz_ListRoleMembers(t *testing.T) {
	captured := authz.ListRoleMembersQuery{}
	svc := &fakeAuthzService{
		listRoleMembersFn: func(_ context.Context, q *authz.ListRoleMembersQuery) ([]*authz.UserAppRoleDTO, error) {
			captured = *q
			return []*authz.UserAppRoleDTO{
				{UserID: "u1", AppID: "a1", RoleID: "r1", TenantID: "t1", AssignedAt: "2026-01-01T00:00:00Z"},
				{UserID: "u2", AppID: "a1", RoleID: "r1", TenantID: "t1", AssignedAt: "2026-01-02T00:00:00Z"},
			}, nil
		},
	}

	r := chi.NewRouter()
	MountAuthz(r, svc, allowAll)

	req := httptest.NewRequest(http.MethodGet, "/roles/r1/users", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	if captured.RoleID != "r1" {
		t.Fatalf("role id not forwarded: %+v", captured)
	}

	var got []AuthzUserAppRoleResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(got) != 2 || got[0].UserID != "u1" || got[1].UserID != "u2" {
		t.Fatalf("unexpected response: %+v", got)
	}
}
