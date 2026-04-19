package domain

import "errors"

var (
	ErrTenantNotFound      = errors.New("tenant not found")
	ErrTenantAlreadyExists = errors.New("tenant already exists")
	ErrAppNotFound         = errors.New("application not found")
	ErrAppAlreadyExists    = errors.New("application already exists")
	ErrClientIDTaken       = errors.New("client_id already taken")
)
