package query

type CheckResourcePermission struct {
	UserID       string
	AppID        string
	ResourceType string
	ResourceID   string
	Action       string
}

type ListResourcePermissions struct {
	UserID string
	AppID  string
}

type ListPermissionDefinitions struct {
	AppID string
}
