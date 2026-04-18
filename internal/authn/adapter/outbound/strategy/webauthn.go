package strategy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/go-webauthn/webauthn/protocol"

	authnDomain "openiam/internal/authn/domain"
	shared "openiam/internal/shared/domain"
)

const webAuthnChallengeTTL = 5 * time.Minute

type WebAuthnConfig struct {
	RPID          string   // e.g. "example.com"
	RPDisplayName string   // e.g. "Example Inc."
	RPOrigins     []string // e.g. ["https://example.com"]
}

type webAuthnLoginParams struct {
	CredentialID      string `json:"credential_id"`
	RawID             string `json:"raw_id"`
	Type              string `json:"type"`
	AuthenticatorData string `json:"authenticator_data"`
	ClientDataJSON    string `json:"client_data_json"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"user_handle"`
	ChallengeID       string `json:"challenge_id"`
}

type WebAuthnStrategy struct {
	wa             *gowebauthn.WebAuthn
	credRepo       authnDomain.CredentialRepository
	userProvider   authnDomain.UserInfoProvider
	challengeStore authnDomain.ChallengeStore
}

func NewWebAuthnStrategy(cfg WebAuthnConfig, credRepo authnDomain.CredentialRepository, userProvider authnDomain.UserInfoProvider, store authnDomain.ChallengeStore) (*WebAuthnStrategy, error) {
	wa, err := gowebauthn.New(&gowebauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("init webauthn: %w", err)
	}

	return &WebAuthnStrategy{
		wa:             wa,
		credRepo:       credRepo,
		userProvider:   userProvider,
		challengeStore: store,
	}, nil
}

func (s *WebAuthnStrategy) Type() authnDomain.CredentialType {
	return authnDomain.CredentialWebAuthn
}

// Challenge starts a discoverable login (passkey) ceremony.
func (s *WebAuthnStrategy) Challenge(ctx context.Context, req *authnDomain.ChallengeRequest) (*authnDomain.ChallengeResponse, error) {
	assertion, sessionData, err := s.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, fmt.Errorf("begin discoverable login: %w", err)
	}

	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		return nil, fmt.Errorf("marshal session: %w", err)
	}

	challengeID := fmt.Sprintf("webauthn:%s:%s", req.AppID, sessionData.Challenge)

	if err := s.challengeStore.Save(ctx, challengeID, sessionJSON, webAuthnChallengeTTL); err != nil {
		return nil, fmt.Errorf("save challenge: %w", err)
	}

	optionsJSON, err := json.Marshal(assertion.Response)
	if err != nil {
		return nil, fmt.Errorf("marshal options: %w", err)
	}

	var optionsMap map[string]any
	_ = json.Unmarshal(optionsJSON, &optionsMap)

	expiresAt := time.Now().Add(webAuthnChallengeTTL)
	return &authnDomain.ChallengeResponse{
		ChallengeID: challengeID,
		Provider:    string(authnDomain.CredentialWebAuthn),
		Data:        optionsMap,
		ExpiresAt:   expiresAt,
	}, nil
}

// Authenticate completes the WebAuthn assertion ceremony.
func (s *WebAuthnStrategy) Authenticate(ctx context.Context, req *authnDomain.AuthnRequest) (*authnDomain.AuthnResult, error) {
	var p webAuthnLoginParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return nil, shared.ErrInvalidCredential
	}
	if p.ChallengeID == "" || p.RawID == "" || p.Signature == "" {
		return nil, shared.ErrInvalidCredential
	}

	sessionJSON, err := s.challengeStore.Get(ctx, p.ChallengeID)
	if err != nil {
		return nil, shared.ErrChallengeNotFound
	}

	var sessionData gowebauthn.SessionData
	if err := json.Unmarshal(sessionJSON, &sessionData); err != nil {
		return nil, shared.ErrChallengeInvalid
	}

	_ = s.challengeStore.Delete(ctx, p.ChallengeID)

	parsedResponse, err := buildAssertionResponse(p)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", shared.ErrInvalidCredential, err)
	}

	credSubject := base64.RawURLEncoding.EncodeToString(parsedResponse.RawID)

	cred, err := s.credRepo.FindBySubjectAndType(ctx, credSubject, req.AppID, authnDomain.CredentialWebAuthn)
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

	waUser := &webauthnUser{
		id:          []byte(cred.UserID),
		credentials: []gowebauthn.Credential{domainCredToWebAuthn(cred)},
	}

	validatedCred, err := s.wa.ValidateLogin(waUser, sessionData, parsedResponse)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", shared.ErrInvalidCredential, err)
	}

	cred.MarkUsed()
	if validatedCred != nil {
		cred.Metadata["sign_count"] = validatedCred.Authenticator.SignCount
	}
	_ = s.credRepo.Update(ctx, cred)

	return &authnDomain.AuthnResult{
		UserID:   cred.UserID,
		TenantID: info.TenantID,
		Subject:  credSubject,
	}, nil
}

// buildAssertionResponse reconstructs a ParsedCredentialAssertionData from our flat params.
func buildAssertionResponse(p webAuthnLoginParams) (*protocol.ParsedCredentialAssertionData, error) {
	rawID, err := base64.RawURLEncoding.DecodeString(p.RawID)
	if err != nil {
		return nil, fmt.Errorf("decode rawId: %w", err)
	}
	authData, err := base64.RawURLEncoding.DecodeString(p.AuthenticatorData)
	if err != nil {
		return nil, fmt.Errorf("decode authenticatorData: %w", err)
	}
	clientDataJSON, err := base64.RawURLEncoding.DecodeString(p.ClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("decode clientDataJSON: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(p.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	var userHandle []byte
	if p.UserHandle != "" {
		userHandle, err = base64.RawURLEncoding.DecodeString(p.UserHandle)
		if err != nil {
			return nil, fmt.Errorf("decode userHandle: %w", err)
		}
	}

	car := protocol.CredentialAssertionResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   p.CredentialID,
				Type: "public-key",
			},
			RawID:                  rawID,
			ClientExtensionResults: map[string]any{},
		},
		AssertionResponse: protocol.AuthenticatorAssertionResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{
				ClientDataJSON: clientDataJSON,
			},
			AuthenticatorData: authData,
			Signature:         sig,
			UserHandle:        userHandle,
		},
	}

	return car.Parse()
}

func domainCredToWebAuthn(c *authnDomain.Credential) gowebauthn.Credential {
	credID, _ := base64.RawURLEncoding.DecodeString(c.CredentialSubject)
	pubKey, _ := base64.RawURLEncoding.DecodeString(safeString(c.PublicKey))

	var signCount uint32
	if sc, ok := c.Metadata["sign_count"]; ok {
		switch v := sc.(type) {
		case float64:
			signCount = uint32(v)
		case uint32:
			signCount = v
		}
	}

	return gowebauthn.Credential{
		ID:        credID,
		PublicKey: pubKey,
		Authenticator: gowebauthn.Authenticator{
			SignCount: signCount,
		},
	}
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// webauthnUser adapts our user model to go-webauthn's User interface.
type webauthnUser struct {
	id          []byte
	credentials []gowebauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte                         { return u.id }
func (u *webauthnUser) WebAuthnName() string                       { return string(u.id) }
func (u *webauthnUser) WebAuthnDisplayName() string                { return string(u.id) }
func (u *webauthnUser) WebAuthnCredentials() []gowebauthn.Credential { return u.credentials }
