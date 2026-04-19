package domain

import (
	"context"
	"errors"
	"testing"

	shared "openiam/internal/shared/domain"
)

type fakeUserRepo struct {
	exists bool
	err    error
}

func (f *fakeUserRepo) Save(context.Context, *User) error { return nil }

func (f *fakeUserRepo) FindByID(context.Context, shared.UserID) (*User, error) { return nil, nil }

func (f *fakeUserRepo) FindByEmail(context.Context, shared.TenantID, Email) (*User, error) {
	return nil, nil
}

func (f *fakeUserRepo) ExistsByEmail(context.Context, shared.TenantID, Email) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.exists, nil
}

func TestUserDomainService_CheckEmailUniqueness(t *testing.T) {
	email := NewEmailFromTrusted("alice@example.com")
	tenantID := shared.NewTenantID()

	t.Run("email available", func(t *testing.T) {
		svc := NewUserDomainService(&fakeUserRepo{exists: false})
		if err := svc.CheckEmailUniqueness(context.Background(), tenantID, email); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("email already exists", func(t *testing.T) {
		svc := NewUserDomainService(&fakeUserRepo{exists: true})
		err := svc.CheckEmailUniqueness(context.Background(), tenantID, email)
		if err != ErrEmailAlreadyTaken {
			t.Fatalf("unexpected error: got %v, want %v", err, ErrEmailAlreadyTaken)
		}
	})

	t.Run("repository error passthrough", func(t *testing.T) {
		repoErr := errors.New("repo down")
		svc := NewUserDomainService(&fakeUserRepo{err: repoErr})
		err := svc.CheckEmailUniqueness(context.Background(), tenantID, email)
		if !errors.Is(err, repoErr) {
			t.Fatalf("expected repo error passthrough, got %v", err)
		}
	})
}
