package strategy

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"openiam/internal/authn/domain"
	identityDomain "openiam/internal/identity/domain"
	shared "openiam/internal/shared/domain"
)

const smsChallengeTTL = 5 * time.Minute

type smsChallengeParams struct {
	Phone string `json:"phone"`
}

type smsVerifyParams struct {
	Phone string `json:"phone"`
	Code  string `json:"code"`
}

type smsChallengeData struct {
	Phone string `json:"phone"`
	Code  string `json:"code"`
	AppID string `json:"app_id"`
}

type SMSSender interface {
	Send(ctx context.Context, phone, code string) error
}

type SMSStrategy struct {
	credRepo       domain.CredentialRepository
	userProvider   domain.UserInfoProvider
	challengeStore domain.ChallengeStore
	sender         SMSSender
}

func NewSMSStrategy(credRepo domain.CredentialRepository, userProvider domain.UserInfoProvider, store domain.ChallengeStore, sender SMSSender) *SMSStrategy {
	return &SMSStrategy{
		credRepo:       credRepo,
		userProvider:   userProvider,
		challengeStore: store,
		sender:         sender,
	}
}

func (s *SMSStrategy) Type() domain.CredentialType {
	return domain.CredentialSMS
}

func (s *SMSStrategy) Challenge(ctx context.Context, req *domain.ChallengeRequest) (*domain.ChallengeResponse, error) {
	var p smsChallengeParams
	if err := json.Unmarshal(req.Params, &p); err != nil || p.Phone == "" {
		return nil, domain.ErrInvalidCredential
	}

	code, err := generateDigitCode(6)
	if err != nil {
		return nil, fmt.Errorf("generate code: %w", err)
	}

	challengeID := fmt.Sprintf("sms:%s:%s", req.AppID, p.Phone)

	data, _ := json.Marshal(smsChallengeData{
		Phone: p.Phone,
		Code:  code,
		AppID: string(req.AppID),
	})

	if err := s.challengeStore.Save(ctx, challengeID, data, smsChallengeTTL); err != nil {
		return nil, fmt.Errorf("save challenge: %w", err)
	}

	if err := s.sender.Send(ctx, p.Phone, code); err != nil {
		_ = s.challengeStore.Delete(ctx, challengeID)
		return nil, fmt.Errorf("send sms: %w", err)
	}

	expiresAt := time.Now().Add(smsChallengeTTL)
	return &domain.ChallengeResponse{
		ChallengeID: challengeID,
		Provider:    string(domain.CredentialSMS),
		Data: map[string]any{
			"phone":      p.Phone,
			"expires_at": expiresAt.Format(time.RFC3339),
		},
		ExpiresAt: expiresAt,
	}, nil
}

func (s *SMSStrategy) Authenticate(ctx context.Context, req *domain.AuthnRequest) (*domain.AuthnResult, error) {
	var p smsVerifyParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return nil, domain.ErrInvalidCredential
	}
	if p.Phone == "" || p.Code == "" {
		return nil, domain.ErrInvalidCredential
	}

	challengeID := fmt.Sprintf("sms:%s:%s", req.AppID, p.Phone)
	raw, err := s.challengeStore.Get(ctx, challengeID)
	if err != nil {
		return nil, domain.ErrChallengeNotFound
	}

	var cd smsChallengeData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return nil, domain.ErrChallengeInvalid
	}

	if cd.Code != p.Code {
		return nil, domain.ErrInvalidCredential
	}

	_ = s.challengeStore.Delete(ctx, challengeID)

	cred, err := s.credRepo.FindBySubjectAndType(ctx, p.Phone, req.AppID, domain.CredentialSMS)
	if err != nil {
		return nil, err
	}

	info, err := s.userProvider.GetUserInfo(ctx, cred.UserID)
	if err != nil {
		return nil, err
	}

	switch info.Status {
	case "disabled":
		return nil, identityDomain.ErrUserDisabled
	case "locked":
		return nil, identityDomain.ErrUserLocked
	case "active":
	default:
		return nil, shared.ErrUnauthorized
	}

	cred.MarkUsed()
	_ = s.credRepo.Update(ctx, cred)

	return &domain.AuthnResult{
		UserID:   cred.UserID,
		TenantID: info.TenantID,
		Subject:  cred.CredentialSubject,
	}, nil
}

func generateDigitCode(length int) (string, error) {
	code := make([]byte, length)
	for i := range code {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		code[i] = byte('0') + byte(n.Int64())
	}
	return string(code), nil
}
