package domain

import "errors"

var (
	ErrRoleNotFound             = errors.New("role not found")
	ErrRoleAlreadyExists        = errors.New("role already exists")
	ErrRoleAppMismatch          = errors.New("role does not belong to the target app")
	ErrPermissionAlreadyGranted = errors.New("permission already granted")
	ErrSystemRoleProtected      = errors.New("system role cannot be modified")
)
