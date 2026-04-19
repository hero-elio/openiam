package persistence

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"openiam/internal/authn/domain"
	shared "openiam/internal/shared/domain"
)

const (
	prefixSessionData    = "session:data:"
	prefixSessionRefresh = "session:refresh:"
	prefixSessionUser    = "session:user:"
)

type RedisSessionRepo struct {
	rdb *redis.Client
}

func NewRedisSessionRepo(rdb *redis.Client) *RedisSessionRepo {
	return &RedisSessionRepo{rdb: rdb}
}

type sessionJSON struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	TenantID     string    `json:"tenant_id"`
	AppID        string    `json:"app_id"`
	Provider     string    `json:"provider"`
	RefreshToken string    `json:"refresh_token"`
	UserAgent    string    `json:"user_agent"`
	IPAddress    string    `json:"ip_address"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
	LastActiveAt time.Time `json:"last_active_at"`
}

func (r *RedisSessionRepo) Save(ctx context.Context, session *domain.Session) error {
	data, err := marshalSession(session)
	if err != nil {
		return err
	}
	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		return domain.ErrSessionExpired
	}

	pipe := r.rdb.Pipeline()
	pipe.Set(ctx, prefixSessionData+session.ID.String(), data, ttl)
	pipe.Set(ctx, prefixSessionRefresh+session.RefreshToken, session.ID.String(), ttl)
	pipe.SAdd(ctx, prefixSessionUser+session.UserID.String(), session.ID.String())
	pipe.Expire(ctx, prefixSessionUser+session.UserID.String(), 30*24*time.Hour)
	_, err = pipe.Exec(ctx)
	return err
}

func (r *RedisSessionRepo) FindByID(ctx context.Context, id shared.SessionID) (*domain.Session, error) {
	data, err := r.rdb.Get(ctx, prefixSessionData+id.String()).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, domain.ErrSessionNotFound
		}
		return nil, err
	}
	return unmarshalSession(data)
}

func (r *RedisSessionRepo) FindByRefreshToken(ctx context.Context, refreshToken string) (*domain.Session, error) {
	sessionID, err := r.rdb.Get(ctx, prefixSessionRefresh+refreshToken).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, domain.ErrSessionNotFound
		}
		return nil, err
	}
	return r.FindByID(ctx, shared.SessionID(sessionID))
}

func (r *RedisSessionRepo) Update(ctx context.Context, session *domain.Session) error {
	oldData, err := r.rdb.Get(ctx, prefixSessionData+session.ID.String()).Bytes()
	if err != nil {
		if err == redis.Nil {
			return domain.ErrSessionNotFound
		}
		return err
	}

	oldSession, err := unmarshalSession(oldData)
	if err != nil {
		return err
	}

	data, err := marshalSession(session)
	if err != nil {
		return err
	}
	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		return domain.ErrSessionExpired
	}

	pipe := r.rdb.Pipeline()
	if oldSession.RefreshToken != session.RefreshToken {
		pipe.Del(ctx, prefixSessionRefresh+oldSession.RefreshToken)
		pipe.Set(ctx, prefixSessionRefresh+session.RefreshToken, session.ID.String(), ttl)
	}
	pipe.Set(ctx, prefixSessionData+session.ID.String(), data, ttl)
	_, err = pipe.Exec(ctx)
	return err
}

func (r *RedisSessionRepo) Delete(ctx context.Context, id shared.SessionID) error {
	data, err := r.rdb.Get(ctx, prefixSessionData+id.String()).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil
		}
		return err
	}

	session, err := unmarshalSession(data)
	if err != nil {
		return err
	}

	pipe := r.rdb.Pipeline()
	pipe.Del(ctx, prefixSessionData+id.String())
	pipe.Del(ctx, prefixSessionRefresh+session.RefreshToken)
	pipe.SRem(ctx, prefixSessionUser+session.UserID.String(), id.String())
	_, err = pipe.Exec(ctx)
	return err
}

func (r *RedisSessionRepo) DeleteByUser(ctx context.Context, userID shared.UserID) error {
	key := prefixSessionUser + userID.String()
	ids, err := r.rdb.SMembers(ctx, key).Result()
	if err != nil {
		return err
	}

	for _, id := range ids {
		if err := r.Delete(ctx, shared.SessionID(id)); err != nil {
			return fmt.Errorf("delete session %s: %w", id, err)
		}
	}
	r.rdb.Del(ctx, key)
	return nil
}

func (r *RedisSessionRepo) ListByUser(ctx context.Context, userID shared.UserID) ([]*domain.Session, error) {
	ids, err := r.rdb.SMembers(ctx, prefixSessionUser+userID.String()).Result()
	if err != nil {
		return nil, err
	}

	if len(ids) == 0 {
		return nil, nil
	}

	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = prefixSessionData + id
	}

	results, err := r.rdb.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}

	sessions := make([]*domain.Session, 0, len(results))
	for _, val := range results {
		if val == nil {
			continue
		}
		s, err := unmarshalSession([]byte(val.(string)))
		if err != nil {
			continue
		}
		sessions = append(sessions, s)
	}
	return sessions, nil
}

func marshalSession(s *domain.Session) ([]byte, error) {
	return json.Marshal(sessionJSON{
		ID:           s.ID.String(),
		UserID:       s.UserID.String(),
		TenantID:     s.TenantID.String(),
		AppID:        s.AppID.String(),
		Provider:     s.Provider,
		RefreshToken: s.RefreshToken,
		UserAgent:    s.UserAgent,
		IPAddress:    s.IPAddress,
		ExpiresAt:    s.ExpiresAt,
		CreatedAt:    s.CreatedAt,
		LastActiveAt: s.LastActiveAt,
	})
}

func unmarshalSession(data []byte) (*domain.Session, error) {
	var j sessionJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, err
	}
	return &domain.Session{
		ID:           shared.SessionID(j.ID),
		UserID:       shared.UserID(j.UserID),
		TenantID:     shared.TenantID(j.TenantID),
		AppID:        shared.AppID(j.AppID),
		Provider:     j.Provider,
		RefreshToken: j.RefreshToken,
		UserAgent:    j.UserAgent,
		IPAddress:    j.IPAddress,
		ExpiresAt:    j.ExpiresAt,
		CreatedAt:    j.CreatedAt,
		LastActiveAt: j.LastActiveAt,
	}, nil
}
