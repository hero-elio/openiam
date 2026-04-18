package token

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"openiam/internal/authn/domain"
)

type JWTConfig struct {
	Secret         string
	Issuer         string
	AccessTokenTTL time.Duration
}

type JWTProvider struct {
	config JWTConfig
}

func NewJWTProvider(config JWTConfig) *JWTProvider {
	return &JWTProvider{config: config}
}

func (p *JWTProvider) Generate(claims domain.TokenClaims) (*domain.TokenPair, error) {
	now := time.Now()
	claims.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    p.config.Issuer,
		Subject:   claims.UserID,
		ExpiresAt: jwt.NewNumericDate(now.Add(p.config.AccessTokenTTL)),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        uuid.New().String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err := token.SignedString([]byte(p.config.Secret))
	if err != nil {
		return nil, err
	}

	refreshToken := uuid.New().String()

	return &domain.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(p.config.AccessTokenTTL.Seconds()),
	}, nil
}

func (p *JWTProvider) Validate(raw string) (*domain.TokenClaims, error) {
	claims := &domain.TokenClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(p.config.Secret), nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, jwt.ErrSignatureInvalid
	}
	return claims, nil
}
