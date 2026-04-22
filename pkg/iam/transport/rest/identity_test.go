package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"openiam/pkg/iam/identity"
)

type fakeIdentityService struct {
	identity.Service

	listFn func(ctx context.Context, q *identity.ListUsersQuery) ([]*identity.UserDTO, error)
}

func (f *fakeIdentityService) ListUsers(ctx context.Context, q *identity.ListUsersQuery) ([]*identity.UserDTO, error) {
	if f.listFn == nil {
		return nil, nil
	}
	return f.listFn(ctx, q)
}

func TestMountIdentity_ListUsers(t *testing.T) {
	captured := identity.ListUsersQuery{}
	svc := &fakeIdentityService{
		listFn: func(_ context.Context, q *identity.ListUsersQuery) ([]*identity.UserDTO, error) {
			captured = *q
			return []*identity.UserDTO{
				{ID: "u1", Email: "a@example.com", TenantID: "t1", Status: "active", CreatedAt: "2026-01-01T00:00:00Z"},
				{ID: "u2", Email: "b@example.com", TenantID: "t1", Status: "active", CreatedAt: "2026-01-02T00:00:00Z"},
			}, nil
		},
	}

	r := chi.NewRouter()
	MountIdentity(r, svc, allowAll)

	req := httptest.NewRequest(http.MethodGet, "/?tenant_id=t1&email_like=%25example%25&limit=20&offset=5", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	if captured.TenantID != "t1" || captured.EmailLike != "%example%" || captured.Limit != 20 || captured.Offset != 5 {
		t.Fatalf("query not forwarded: %+v", captured)
	}

	var got []IdentityUserResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(got) != 2 || got[0].ID != "u1" || got[1].Email != "b@example.com" {
		t.Fatalf("unexpected response: %+v", got)
	}
}

func TestMountIdentity_ListUsers_Forbidden(t *testing.T) {
	svc := &fakeIdentityService{}
	r := chi.NewRouter()
	MountIdentity(r, svc, denyAll)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status: want 403, got %d", w.Code)
	}
}

func denyAll(_ context.Context, _, _ string) error { return errDenied }

var errDenied = denyErr{}

type denyErr struct{}

func (denyErr) Error() string { return "denied" }
