package strategy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	siwe "github.com/spruceid/siwe-go"

	authnDomain "openiam/internal/authn/domain"
	shared "openiam/internal/shared/domain"
)

const siweChallengeTTL = 5 * time.Minute

type SIWEConfig struct {
	Domain string // e.g. "example.com", matched against SIWE message domain
}

type siweLoginParams struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

type siweChallengeData struct {
	Nonce string `json:"nonce"`
	AppID string `json:"app_id"`
}

type SIWEStrategy struct {
	cfg            SIWEConfig
	credRepo       authnDomain.CredentialRepository
	userProvider   authnDomain.UserInfoProvider
	externalIDP    authnDomain.ExternalIdentityProvider
	challengeStore authnDomain.ChallengeStore
}

func NewSIWEStrategy(cfg SIWEConfig, credRepo authnDomain.CredentialRepository, userProvider authnDomain.UserInfoProvider, externalIDP authnDomain.ExternalIdentityProvider, store authnDomain.ChallengeStore) *SIWEStrategy {
	return &SIWEStrategy{
		cfg:            cfg,
		credRepo:       credRepo,
		userProvider:   userProvider,
		externalIDP:    externalIDP,
		challengeStore: store,
	}
}

func (s *SIWEStrategy) Type() authnDomain.CredentialType {
	return authnDomain.CredentialSIWE
}

func (s *SIWEStrategy) Challenge(ctx context.Context, req *authnDomain.ChallengeRequest) (*authnDomain.ChallengeResponse, error) {
	nonce, err := generateNonce(16)
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	challengeID := fmt.Sprintf("siwe:%s:%s", req.AppID, nonce)

	data, _ := json.Marshal(siweChallengeData{
		Nonce: nonce,
		AppID: string(req.AppID),
	})

	if err := s.challengeStore.Save(ctx, challengeID, data, siweChallengeTTL); err != nil {
		return nil, fmt.Errorf("save challenge: %w", err)
	}

	expiresAt := time.Now().Add(siweChallengeTTL)
	return &authnDomain.ChallengeResponse{
		ChallengeID: challengeID,
		Provider:    string(authnDomain.CredentialSIWE),
		Data: map[string]any{
			"nonce":      nonce,
			"domain":     s.cfg.Domain,
			"expires_at": expiresAt.Format(time.RFC3339),
		},
		ExpiresAt: expiresAt,
	}, nil
}

// Authenticate verifies a SIWE message + signature and resolves the signer
// to a CAIP-10 account identifier (eip155:{chainId}:{address}).
// If no credential exists, a new user and credential are auto-created.
// See https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-10.md
func (s *SIWEStrategy) Authenticate(ctx context.Context, req *authnDomain.AuthnRequest) (*authnDomain.AuthnResult, error) {
	caip10, err := s.verifySIWE(ctx, req)
	if err != nil {
		return nil, err
	}

	cred, err := s.credRepo.FindBySubjectAndType(ctx, caip10, req.AppID, authnDomain.CredentialSIWE)
	if err != nil {
		if !errors.Is(err, shared.ErrCredentialNotFound) {
			return nil, err
		}
		info, createErr := s.externalIDP.EnsureExternalUser(ctx, &authnDomain.EnsureExternalUserRequest{
			AppID:             req.AppID,
			TenantID:          "default",
			Provider:          string(authnDomain.CredentialSIWE),
			CredentialSubject: caip10,
		})
		if createErr != nil {
			return nil, createErr
		}
		return &authnDomain.AuthnResult{
			UserID:   info.UserID,
			TenantID: info.TenantID,
			Subject:  caip10,
			IsNew:    true,
		}, nil
	}

	info, err := s.userProvider.GetUserInfo(ctx, cred.UserID)
	if err != nil {
		return nil, err
	}

	switch info.Status {
	case "disabled":
		return nil, shared.ErrUserDisabled
	case "locked":
		return nil, shared.ErrUserLocked
	case "active":
	default:
		return nil, shared.ErrUnauthorized
	}

	cred.MarkUsed()
	_ = s.credRepo.Update(ctx, cred)

	return &authnDomain.AuthnResult{
		UserID:   cred.UserID,
		TenantID: info.TenantID,
		Subject:  caip10,
	}, nil
}

// VerifyAndBind verifies a SIWE proof and binds the credential to the given user.
func (s *SIWEStrategy) VerifyAndBind(ctx context.Context, req *authnDomain.AuthnRequest, userID shared.UserID) error {
	caip10, err := s.verifySIWE(ctx, req)
	if err != nil {
		return err
	}

	existing, err := s.credRepo.FindBySubjectAndType(ctx, caip10, req.AppID, authnDomain.CredentialSIWE)
	if err == nil {
		if existing.UserID != userID {
			return shared.ErrCredentialAlreadyBound
		}
		return shared.ErrCredentialAlreadyExists
	}
	if !errors.Is(err, shared.ErrCredentialNotFound) {
		return err
	}

	cred := authnDomain.NewCredential(userID, req.AppID, authnDomain.CredentialSIWE, string(authnDomain.CredentialSIWE), caip10)
	return s.credRepo.Save(ctx, cred)
}

// verifySIWE validates a SIWE message+signature and returns the CAIP-10 subject.
func (s *SIWEStrategy) verifySIWE(ctx context.Context, req *authnDomain.AuthnRequest) (string, error) {
	var p siweLoginParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return "", shared.ErrInvalidCredential
	}
	if p.Message == "" || p.Signature == "" {
		return "", shared.ErrInvalidCredential
	}

	msg, err := siwe.ParseMessage(p.Message)
	if err != nil {
		return "", fmt.Errorf("%w: %v", shared.ErrInvalidCredential, err)
	}

	nonce := msg.GetNonce()
	challengeID := fmt.Sprintf("siwe:%s:%s", req.AppID, nonce)

	raw, err := s.challengeStore.Get(ctx, challengeID)
	if err != nil {
		return "", shared.ErrChallengeNotFound
	}

	var cd siweChallengeData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return "", shared.ErrChallengeInvalid
	}

	if cd.Nonce != nonce || cd.AppID != string(req.AppID) {
		return "", shared.ErrChallengeInvalid
	}

	expectedDomain := s.cfg.Domain
	_, err = msg.Verify(p.Signature, &expectedDomain, &nonce, nil)
	if err != nil {
		return "", fmt.Errorf("%w: %v", shared.ErrInvalidCredential, err)
	}

	_ = s.challengeStore.Delete(ctx, challengeID)

	return fmt.Sprintf("eip155:%d:%s", msg.GetChainID(), msg.GetAddress().Hex()), nil
}

func generateNonce(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
