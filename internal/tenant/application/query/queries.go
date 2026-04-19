package query

type GetTenant struct {
	TenantID string
}

type GetApplication struct {
	AppID string
}

type ListApplications struct {
	TenantID string
}
