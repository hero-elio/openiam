package query

type ListRoles struct {
	AppID string
}

type ListUserRoles struct {
	UserID string
	AppID  string
}

type ListRoleMembers struct {
	RoleID string
}
