package command

import "encoding/json"

type BindCredential struct {
	UserID   string
	AppID    string
	Provider string
	Params   json.RawMessage
}
