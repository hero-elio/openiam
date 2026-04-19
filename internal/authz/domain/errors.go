package domain

import "errors"

var (
	ErrRoleNotFound             = errors.New("role not found")
	ErrRoleAlreadyExists        = errors.New("role already exists")
	ErrPermissionAlreadyGranted = errors.New("permission already granted")
	ErrSystemRoleProtected      = errors.New("system role cannot be modified")
)
