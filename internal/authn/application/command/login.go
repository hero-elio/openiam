package command

type Login struct {
	AppID     string
	Provider  string
	Params    map[string]string
	UserAgent string
	IPAddress string
}
