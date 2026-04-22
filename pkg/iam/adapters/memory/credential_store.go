package memory

import (
	"context"
	"sync"

	authnDomain "openiam/internal/authn/domain"
	shared "openiam/internal/shared/domain"
	"openiam/pkg/iam/authn"
)

// CredentialStore is an in-process implementation of
// authn.CredentialStore. The map is keyed by credential id; secondary
// indexes for the lookup methods are derived on demand to keep the
// implementation simple.
type CredentialStore struct {
	mu          sync.RWMutex
	credentials map[shared.CredentialID]*authn.Credential
}

// NewCredentialStore returns an empty store.
func NewCredentialStore() *CredentialStore {
	return &CredentialStore{credentials: make(map[shared.CredentialID]*authn.Credential)}
}

func (s *CredentialStore) Save(_ context.Context, cred *authn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, existing := range s.credentials {
		if existing.AppID == cred.AppID &&
			existing.Type == cred.Type &&
			existing.CredentialSubject == cred.CredentialSubject {
			return authnDomain.ErrCredentialAlreadyBound
		}
	}
	s.credentials[cred.ID] = copyCredential(cred)
	return nil
}

func (s *CredentialStore) FindByID(_ context.Context, id shared.CredentialID) (*authn.Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cred, ok := s.credentials[id]
	if !ok {
		return nil, authnDomain.ErrCredentialNotFound
	}
	return copyCredential(cred), nil
}

func (s *CredentialStore) FindByUserAndType(_ context.Context, userID shared.UserID, appID shared.AppID, credType authn.CredentialType) (*authn.Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, cred := range s.credentials {
		if cred.UserID == userID && cred.AppID == appID && cred.Type == credType {
			return copyCredential(cred), nil
		}
	}
	return nil, authnDomain.ErrCredentialNotFound
}

func (s *CredentialStore) FindBySubjectAndType(_ context.Context, subject string, appID shared.AppID, credType authn.CredentialType) (*authn.Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, cred := range s.credentials {
		if cred.CredentialSubject == subject && cred.AppID == appID && cred.Type == credType {
			return copyCredential(cred), nil
		}
	}
	return nil, authnDomain.ErrCredentialNotFound
}

func (s *CredentialStore) Update(_ context.Context, cred *authn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.credentials[cred.ID]; !ok {
		return authnDomain.ErrCredentialNotFound
	}
	s.credentials[cred.ID] = copyCredential(cred)
	return nil
}

func (s *CredentialStore) Delete(_ context.Context, id shared.CredentialID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.credentials, id)
	return nil
}

func (s *CredentialStore) ListByUser(_ context.Context, userID shared.UserID) ([]*authn.Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*authn.Credential
	for _, cred := range s.credentials {
		if cred.UserID == userID {
			out = append(out, copyCredential(cred))
		}
	}
	return out, nil
}

func copyCredential(c *authn.Credential) *authn.Credential {
	dup := *c
	if c.Secret != nil {
		s := *c.Secret
		dup.Secret = &s
	}
	if c.PublicKey != nil {
		k := *c.PublicKey
		dup.PublicKey = &k
	}
	if c.Metadata != nil {
		dup.Metadata = make(map[string]any, len(c.Metadata))
		for k, v := range c.Metadata {
			dup.Metadata[k] = v
		}
	}
	return &dup
}

var _ authn.CredentialStore = (*CredentialStore)(nil)
