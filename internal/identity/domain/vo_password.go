package domain

import (
	shared "openiam/internal/shared/domain"

	"github.com/alexedwards/argon2id"
)

type Password struct {
	hash string
}

func NewPassword(raw string) (Password, error) {
	if len(raw) < 8 {
		return Password{}, shared.ErrPasswordTooShort
	}
	hash, err := argon2id.CreateHash(raw, argon2id.DefaultParams)
	if err != nil {
		return Password{}, err
	}
	return Password{hash: hash}, nil
}

func NewPasswordFromHash(hash string) Password {
	return Password{hash: hash}
}

func (p Password) Verify(raw string) bool {
	match, _ := argon2id.ComparePasswordAndHash(raw, p.hash)
	return match
}

func (p Password) Hash() string  { return p.hash }
func (p Password) IsEmpty() bool { return p.hash == "" }
