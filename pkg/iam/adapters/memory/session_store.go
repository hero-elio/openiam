package memory

import (
	"context"
	"sync"

	authnDomain "openiam/internal/authn/domain"
	shared "openiam/internal/shared/domain"
	"openiam/pkg/iam/authn"
)

// SessionStore is an in-process implementation of authn.SessionStore.
// Sessions never expire on their own — IsExpired-style checks happen
// in the application layer based on the embedded ExpiresAt timestamp.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[shared.SessionID]*authn.Session
}

// NewSessionStore returns an empty store.
func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[shared.SessionID]*authn.Session)}
}

func (s *SessionStore) Save(_ context.Context, session *authn.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = copySession(session)
	return nil
}

func (s *SessionStore) FindByID(_ context.Context, id shared.SessionID) (*authn.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[id]
	if !ok {
		return nil, authnDomain.ErrSessionNotFound
	}
	return copySession(session), nil
}

func (s *SessionStore) FindByRefreshToken(_ context.Context, refreshToken string) (*authn.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, session := range s.sessions {
		if session.RefreshToken == refreshToken {
			return copySession(session), nil
		}
	}
	return nil, authnDomain.ErrSessionNotFound
}

func (s *SessionStore) Update(_ context.Context, session *authn.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[session.ID]; !ok {
		return authnDomain.ErrSessionNotFound
	}
	s.sessions[session.ID] = copySession(session)
	return nil
}

func (s *SessionStore) Delete(_ context.Context, id shared.SessionID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}

func (s *SessionStore) DeleteByUser(_ context.Context, userID shared.UserID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, session := range s.sessions {
		if session.UserID == userID {
			delete(s.sessions, id)
		}
	}
	return nil
}

func (s *SessionStore) ListByUser(_ context.Context, userID shared.UserID) ([]*authn.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*authn.Session
	for _, session := range s.sessions {
		if session.UserID == userID {
			out = append(out, copySession(session))
		}
	}
	return out, nil
}

func copySession(s *authn.Session) *authn.Session {
	dup := *s
	return &dup
}

var _ authn.SessionStore = (*SessionStore)(nil)
