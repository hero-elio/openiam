package command

import "encoding/json"

type Login struct {
	AppID     string
	Provider  string
	Params    json.RawMessage
	UserAgent string
	IPAddress string
}
