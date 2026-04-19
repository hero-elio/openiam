package command

type CreateTenant struct {
	Name string
}

type CreateApplication struct {
	TenantID  string
	Name      string
	CreatedBy string
}

type UpdateApplication struct {
	AppID        string
	Name         string
	RedirectURIs []string
	Scopes       []string
}
