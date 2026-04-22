package persistence

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	"openiam/internal/authn/domain"
)

const prefixChallenge = "challenge:"

type RedisChallengeStore struct {
	rdb *redis.Client
}

func NewRedisChallengeStore(rdb *redis.Client) *RedisChallengeStore {
	return &RedisChallengeStore{rdb: rdb}
}

func (s *RedisChallengeStore) Save(ctx context.Context, challengeID string, data []byte, ttl time.Duration) error {
	return s.rdb.Set(ctx, prefixChallenge+challengeID, data, ttl).Err()
}

func (s *RedisChallengeStore) Get(ctx context.Context, challengeID string) ([]byte, error) {
	data, err := s.rdb.Get(ctx, prefixChallenge+challengeID).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, domain.ErrChallengeNotFound
		}
		return nil, err
	}
	return data, nil
}

func (s *RedisChallengeStore) Delete(ctx context.Context, challengeID string) error {
	return s.rdb.Del(ctx, prefixChallenge+challengeID).Err()
}
