package strategy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
	challengeStore authnDomain.ChallengeStore
}

func NewSIWEStrategy(cfg SIWEConfig, credRepo authnDomain.CredentialRepository, userProvider authnDomain.UserInfoProvider, store authnDomain.ChallengeStore) *SIWEStrategy {
	return &SIWEStrategy{
		cfg:            cfg,
		credRepo:       credRepo,
		userProvider:   userProvider,
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
// See https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-10.md
func (s *SIWEStrategy) Authenticate(ctx context.Context, req *authnDomain.AuthnRequest) (*authnDomain.AuthnResult, error) {
	var p siweLoginParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return nil, shared.ErrInvalidCredential
	}
	if p.Message == "" || p.Signature == "" {
		return nil, shared.ErrInvalidCredential
	}

	msg, err := siwe.ParseMessage(p.Message)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", shared.ErrInvalidCredential, err)
	}

	nonce := msg.GetNonce()
	challengeID := fmt.Sprintf("siwe:%s:%s", req.AppID, nonce)

	raw, err := s.challengeStore.Get(ctx, challengeID)
	if err != nil {
		return nil, shared.ErrChallengeNotFound
	}

	var cd siweChallengeData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return nil, shared.ErrChallengeInvalid
	}

	if cd.Nonce != nonce || cd.AppID != string(req.AppID) {
		return nil, shared.ErrChallengeInvalid
	}

	expectedDomain := s.cfg.Domain
	_, err = msg.Verify(p.Signature, &expectedDomain, &nonce, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", shared.ErrInvalidCredential, err)
	}

	_ = s.challengeStore.Delete(ctx, challengeID)

	// CAIP-10: eip155:{chainId}:{checksumAddress}
	caip10 := fmt.Sprintf("eip155:%d:%s", msg.GetChainID(), msg.GetAddress().Hex())

	cred, err := s.credRepo.FindBySubjectAndType(ctx, caip10, req.AppID, authnDomain.CredentialSIWE)
	if err != nil {
		return nil, err
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

func generateNonce(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
