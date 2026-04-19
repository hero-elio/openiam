package domain

import "errors"

var (
	ErrUserNotFound         = errors.New("user not found")
	ErrUserAlreadyExists    = errors.New("user already exists")
	ErrEmailAlreadyTaken    = errors.New("email already taken")
	ErrInvalidEmail         = errors.New("invalid email")
	ErrPasswordTooShort     = errors.New("password must be at least 8 characters")
	ErrInvalidPassword      = errors.New("invalid password")
	ErrUserAlreadyActivated = errors.New("user already activated")
	ErrUserDisabled         = errors.New("user is disabled")
	ErrUserLocked           = errors.New("user is locked")
)
