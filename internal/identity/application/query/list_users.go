package query

type ListUsers struct {
	TenantID  string
	EmailLike string
	Offset    int
	Limit     int
}
