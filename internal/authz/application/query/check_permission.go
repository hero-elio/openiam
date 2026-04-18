package query

type CheckPermission struct {
	UserID   string
	AppID    string
	Resource string
	Action   string
}
