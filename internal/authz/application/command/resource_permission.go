package command

type GrantResourcePermission struct {
	UserID       string
	AppID        string
	TenantID     string
	ResourceType string
	ResourceID   string
	Action       string
	GrantedBy    string
}

type RevokeResourcePermission struct {
	UserID       string
	AppID        string
	ResourceType string
	ResourceID   string
	Action       string
}

type RegisterPermission struct {
	AppID       string
	Resource    string
	Action      string
	Description string
}

type DeletePermission struct {
	AppID    string
	Resource string
	Action   string
}
