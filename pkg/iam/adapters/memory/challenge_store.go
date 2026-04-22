package memory

import (
	"context"
	"sync"
	"time"

	authnDomain "openiam/internal/authn/domain"
	"openiam/pkg/iam/authn"
)

// ChallengeStore is an in-process implementation of authn.ChallengeStore.
// Entries respect their TTL: Get returns ErrChallengeNotFound after the
// recorded expiry, mirroring the behaviour of the Redis adapter.
type ChallengeStore struct {
	mu      sync.Mutex
	entries map[string]challengeEntry
}

type challengeEntry struct {
	data      []byte
	expiresAt time.Time
}

// NewChallengeStore returns an empty store.
func NewChallengeStore() *ChallengeStore {
	return &ChallengeStore{entries: make(map[string]challengeEntry)}
}

func (s *ChallengeStore) Save(_ context.Context, challengeID string, data []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dup := make([]byte, len(data))
	copy(dup, data)
	s.entries[challengeID] = challengeEntry{
		data:      dup,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

func (s *ChallengeStore) Get(_ context.Context, challengeID string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[challengeID]
	if !ok {
		return nil, authnDomain.ErrChallengeNotFound
	}
	if time.Now().After(entry.expiresAt) {
		delete(s.entries, challengeID)
		return nil, authnDomain.ErrChallengeNotFound
	}
	dup := make([]byte, len(entry.data))
	copy(dup, entry.data)
	return dup, nil
}

func (s *ChallengeStore) Delete(_ context.Context, challengeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, challengeID)
	return nil
}

var _ authn.ChallengeStore = (*ChallengeStore)(nil)
