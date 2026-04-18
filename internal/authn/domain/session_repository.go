package domain

import (
	"context"

	shared "openiam/internal/shared/domain"
)

type SessionRepository interface {
	Save(ctx context.Context, session *Session) error
	FindByID(ctx context.Context, id shared.SessionID) (*Session, error)
	FindByRefreshToken(ctx context.Context, refreshToken string) (*Session, error)
	Update(ctx context.Context, session *Session) error
	Delete(ctx context.Context, id shared.SessionID) error
	DeleteByUser(ctx context.Context, userID shared.UserID) error
	ListByUser(ctx context.Context, userID shared.UserID) ([]*Session, error)
}
