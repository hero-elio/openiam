package authn

import (
	"openiam/internal/authn/application/command"
	"openiam/internal/authn/application/query"
)

// Command / query DTOs accepted by Service.
//
// The aliases let internal callers (REST handlers, application service
// methods) keep using command.Login until Phase 5 lifts the canonical
// definition up here. From the SDK consumer's point of view the public
// names (LoginCommand, RegisterCommand, …) are the API.
type (
	LoginCommand          = command.Login
	RegisterCommand       = command.Register
	LogoutCommand         = command.Logout
	RefreshTokenCommand   = command.RefreshToken
	ChallengeCommand      = command.Challenge
	BindCredentialCommand = command.BindCredential
	GetSessionQuery       = query.GetSession
)
