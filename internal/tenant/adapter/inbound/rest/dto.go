package rest

type CreateTenantRequest struct {
	Name string `json:"name"`
}

type CreateApplicationRequest struct {
	Name string `json:"name"`
}

type UpdateApplicationRequest struct {
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
}

type TenantResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

type ApplicationResponse struct {
	ID           string   `json:"id"`
	TenantID     string   `json:"tenant_id"`
	Name         string   `json:"name"`
	ClientID     string   `json:"client_id"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	Status       string   `json:"status"`
	CreatedAt    string   `json:"created_at"`
}

type CreateApplicationResponse struct {
	ApplicationResponse
	ClientSecret string `json:"client_secret"`
}

type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
