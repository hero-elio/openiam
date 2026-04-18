package command

type RegisterExternalUser struct {
	AppID             string
	TenantID          string
	Provider          string
	CredentialSubject string
	PublicKey         string
}
