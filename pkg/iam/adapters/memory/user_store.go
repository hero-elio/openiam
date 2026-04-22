package memory

import (
	"context"
	"sort"
	"strings"
	"sync"

	identityDomain "openiam/internal/identity/domain"
	shared "openiam/internal/shared/domain"
	"openiam/pkg/iam/identity"
)

// UserStore is an in-process implementation of identity.UserStore.
// Users are stored verbatim; lookups by email are case-insensitive on
// the local-part to match the Postgres adapter's CITEXT semantics.
type UserStore struct {
	mu    sync.RWMutex
	users map[shared.UserID]*identityDomain.User
}

// NewUserStore returns an empty store.
func NewUserStore() *UserStore {
	return &UserStore{users: make(map[shared.UserID]*identityDomain.User)}
}

func (s *UserStore) Save(_ context.Context, user *identityDomain.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user.ID] = copyUser(user)
	return nil
}

func (s *UserStore) FindByID(_ context.Context, id shared.UserID) (*identityDomain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[id]
	if !ok {
		return nil, identityDomain.ErrUserNotFound
	}
	return copyUser(user), nil
}

func (s *UserStore) FindByEmail(_ context.Context, tenantID shared.TenantID, email identityDomain.Email) (*identityDomain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	target := strings.ToLower(email.String())
	for _, user := range s.users {
		if user.TenantID == tenantID && strings.ToLower(user.Email.String()) == target {
			return copyUser(user), nil
		}
	}
	return nil, identityDomain.ErrUserNotFound
}

func (s *UserStore) List(_ context.Context, filter identityDomain.ListUsersFilter) ([]*identityDomain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	likeNeedle := strings.ToLower(strings.Trim(filter.EmailLike, "%"))

	matched := make([]*identityDomain.User, 0, len(s.users))
	for _, user := range s.users {
		if !filter.TenantID.IsEmpty() && user.TenantID != filter.TenantID {
			continue
		}
		if likeNeedle != "" && !strings.Contains(strings.ToLower(user.Email.String()), likeNeedle) {
			continue
		}
		matched = append(matched, copyUser(user))
	}

	sort.Slice(matched, func(i, j int) bool {
		return matched[i].CreatedAt.After(matched[j].CreatedAt)
	})

	if filter.Offset > 0 {
		if filter.Offset >= len(matched) {
			return []*identityDomain.User{}, nil
		}
		matched = matched[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(matched) {
		matched = matched[:filter.Limit]
	}
	return matched, nil
}

func (s *UserStore) ExistsByEmail(_ context.Context, tenantID shared.TenantID, email identityDomain.Email) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	target := strings.ToLower(email.String())
	for _, user := range s.users {
		if user.TenantID == tenantID && strings.ToLower(user.Email.String()) == target {
			return true, nil
		}
	}
	return false, nil
}

func copyUser(u *identityDomain.User) *identityDomain.User {
	dup := *u
	return &dup
}

var _ identity.UserStore = (*UserStore)(nil)
