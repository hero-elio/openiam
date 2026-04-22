package domain

import "errors"

var (
	ErrRoleNotFound             = errors.New("role not found")
	ErrRoleAlreadyExists        = errors.New("role already exists")
	ErrRoleAppMismatch          = errors.New("role does not belong to the target app")
	ErrPermissionAlreadyGranted = errors.New("permission already granted")
	ErrSystemRoleProtected      = errors.New("system role cannot be modified")
	// ErrUnknownSubject is returned when authz is asked to attach a
	// role or permission to a user/app that doesn't exist. We refuse
	// here so we don't accumulate ghost grants for typo'd IDs.
	ErrUnknownSubject = errors.New("subject does not exist")
)
