package strategy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/go-webauthn/webauthn/protocol"

	authnDomain "openiam/internal/authn/domain"
	identityDomain "openiam/internal/identity/domain"
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

type webAuthnBindParams struct {
	ChallengeID       string `json:"challenge_id"`
	RawID             string `json:"raw_id"`
	PublicKey         string `json:"public_key"`
	AttestationObject string `json:"attestation_object"`
	ClientDataJSON    string `json:"client_data_json"`
}

type WebAuthnStrategy struct {
	wa             *gowebauthn.WebAuthn
	credRepo       authnDomain.CredentialRepository
	identity       authnDomain.ExternalLoginIdentity
	challengeStore authnDomain.ChallengeStore
	apps           authnDomain.AppDirectory
}

func NewWebAuthnStrategy(
	cfg WebAuthnConfig,
	credRepo authnDomain.CredentialRepository,
	identity authnDomain.ExternalLoginIdentity,
	store authnDomain.ChallengeStore,
	apps authnDomain.AppDirectory,
) (*WebAuthnStrategy, error) {
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
		identity:       identity,
		challengeStore: store,
		apps:           apps,
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
		return nil, authnDomain.ErrInvalidCredential
	}
	if p.ChallengeID == "" || p.RawID == "" || p.Signature == "" {
		var registerPayload webAuthnBindParams
		if err := json.Unmarshal(req.Params, &registerPayload); err != nil {
			return nil, authnDomain.ErrInvalidCredential
		}
		return s.authenticateViaRegistration(ctx, req, registerPayload)
	}

	sessionJSON, err := s.challengeStore.Get(ctx, p.ChallengeID)
	if err != nil {
		return nil, authnDomain.ErrChallengeNotFound
	}

	var sessionData gowebauthn.SessionData
	if err := json.Unmarshal(sessionJSON, &sessionData); err != nil {
		return nil, authnDomain.ErrChallengeInvalid
	}

	_ = s.challengeStore.Delete(ctx, p.ChallengeID)

	parsedResponse, err := buildAssertionResponse(p)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", authnDomain.ErrInvalidCredential, err)
	}

	credSubject := base64.RawURLEncoding.EncodeToString(parsedResponse.RawID)

	cred, err := s.credRepo.FindBySubjectAndType(ctx, credSubject, req.AppID, authnDomain.CredentialWebAuthn)
	if err != nil {
		return nil, err
	}

	info, err := s.identity.GetUserInfo(ctx, cred.UserID)
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

	waUser := &webauthnUser{
		id:          []byte(cred.UserID),
		credentials: []gowebauthn.Credential{domainCredToWebAuthn(cred)},
	}

	validatedCred, err := s.wa.ValidateLogin(waUser, sessionData, parsedResponse)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", authnDomain.ErrInvalidCredential, err)
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

// authenticateViaRegistration supports "first WebAuthn login" by accepting
// an attestation-style payload, creating a user+credential, and issuing login.
func (s *WebAuthnStrategy) authenticateViaRegistration(
	ctx context.Context,
	req *authnDomain.AuthnRequest,
	p webAuthnBindParams,
) (*authnDomain.AuthnResult, error) {
	if p.ChallengeID == "" || p.RawID == "" || p.PublicKey == "" {
		return nil, authnDomain.ErrInvalidCredential
	}

	sessionJSON, err := s.challengeStore.Get(ctx, p.ChallengeID)
	if err != nil {
		return nil, authnDomain.ErrChallengeNotFound
	}
	var sessionData gowebauthn.SessionData
	if err := json.Unmarshal(sessionJSON, &sessionData); err != nil {
		return nil, authnDomain.ErrChallengeInvalid
	}
	_ = sessionData
	_ = s.challengeStore.Delete(ctx, p.ChallengeID)

	existing, err := s.credRepo.FindBySubjectAndType(ctx, p.RawID, req.AppID, authnDomain.CredentialWebAuthn)
	if err == nil {
		info, infoErr := s.identity.GetUserInfo(ctx, existing.UserID)
		if infoErr != nil {
			return nil, infoErr
		}
		return &authnDomain.AuthnResult{
			UserID:   existing.UserID,
			TenantID: info.TenantID,
			Subject:  p.RawID,
			IsNew:    false,
		}, nil
	}
	if !errors.Is(err, authnDomain.ErrCredentialNotFound) {
		return nil, err
	}

	tenantID, lookupErr := s.resolveTenant(ctx, req.AppID)
	if lookupErr != nil {
		return nil, lookupErr
	}
	info, createErr := s.identity.ProvisionExternalUser(ctx, &authnDomain.ProvisionExternalUserRequest{
		AppID:             req.AppID,
		TenantID:          tenantID,
		Provider:          string(authnDomain.CredentialWebAuthn),
		CredentialSubject: p.RawID,
		PublicKey:         p.PublicKey,
	})
	if createErr != nil {
		return nil, createErr
	}

	return &authnDomain.AuthnResult{
		UserID:   info.UserID,
		TenantID: info.TenantID,
		Subject:  p.RawID,
		IsNew:    true,
	}, nil
}

// resolveTenant looks up the tenant that owns the application via the
// AppDirectory port. We require an AppDirectory to be wired so external
// identities cannot leak across tenants under a hard-coded "default".
func (s *WebAuthnStrategy) resolveTenant(ctx context.Context, appID shared.AppID) (shared.TenantID, error) {
	if s.apps == nil {
		return "", fmt.Errorf("webauthn: app directory not configured; cannot resolve tenant for app %s", appID)
	}
	return s.apps.TenantOf(ctx, appID)
}

// VerifyAndBind completes a WebAuthn registration (attestation) ceremony
// and binds the new credential to the given user.
func (s *WebAuthnStrategy) VerifyAndBind(ctx context.Context, req *authnDomain.AuthnRequest, userID shared.UserID) error {
	var p webAuthnBindParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return authnDomain.ErrInvalidCredential
	}
	if p.ChallengeID == "" || p.RawID == "" {
		return authnDomain.ErrInvalidCredential
	}

	sessionJSON, err := s.challengeStore.Get(ctx, p.ChallengeID)
	if err != nil {
		return authnDomain.ErrChallengeNotFound
	}

	var sessionData gowebauthn.SessionData
	if err := json.Unmarshal(sessionJSON, &sessionData); err != nil {
		return authnDomain.ErrChallengeInvalid
	}

	_ = s.challengeStore.Delete(ctx, p.ChallengeID)

	credSubject := p.RawID

	existing, err := s.credRepo.FindBySubjectAndType(ctx, credSubject, req.AppID, authnDomain.CredentialWebAuthn)
	if err == nil {
		if existing.UserID != userID {
			return authnDomain.ErrCredentialAlreadyBound
		}
		return authnDomain.ErrCredentialAlreadyExists
	}
	if !errors.Is(err, authnDomain.ErrCredentialNotFound) {
		return err
	}

	cred := authnDomain.NewCredential(userID, req.AppID, authnDomain.CredentialWebAuthn, string(authnDomain.CredentialWebAuthn), credSubject)
	if p.PublicKey != "" {
		cred.SetPublicKey(p.PublicKey)
	}
	if p.AttestationObject != "" {
		cred.Metadata["attestation_object"] = p.AttestationObject
	}
	return s.credRepo.Save(ctx, cred)
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

func (u *webauthnUser) WebAuthnID() []byte                           { return u.id }
func (u *webauthnUser) WebAuthnName() string                         { return string(u.id) }
func (u *webauthnUser) WebAuthnDisplayName() string                  { return string(u.id) }
func (u *webauthnUser) WebAuthnCredentials() []gowebauthn.Credential { return u.credentials }
