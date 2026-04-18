package command

type GrantPermission struct {
	RoleID   string
	Resource string
	Action   string
}

type RevokePermission struct {
	RoleID   string
	Resource string
	Action   string
}
