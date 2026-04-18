package command

type RegisterUser struct {
	AppID    string
	Provider string
	Email    string
	Password string
	TenantID string
}
