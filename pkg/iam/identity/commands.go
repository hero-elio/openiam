package identity

import (
	"openiam/internal/identity/application/command"
	"openiam/internal/identity/application/query"
)

// Command / query DTOs accepted by Service.
type (
	RegisterUserCommand         = command.RegisterUser
	RegisterExternalUserCommand = command.RegisterExternalUser
	ChangePasswordCommand       = command.ChangePassword
	UpdateProfileCommand        = command.UpdateProfile

	GetUserQuery   = query.GetUser
	ListUsersQuery = query.ListUsers
)
