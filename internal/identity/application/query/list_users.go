package query

type ListUsers struct {
	TenantID string
	Offset   int
	Limit    int
}
