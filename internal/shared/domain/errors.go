package domain

import "errors"

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrInvalidInput  = errors.New("invalid input")
	ErrUnauthorized  = errors.New("unauthorized")
	ErrForbidden     = errors.New("forbidden")
	// ErrConcurrentUpdate signals an optimistic-locking conflict: the
	// caller's snapshot is stale relative to the persisted aggregate.
	ErrConcurrentUpdate = errors.New("concurrent update detected")
)
