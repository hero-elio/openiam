package command

import "encoding/json"

type Challenge struct {
	AppID    string
	Provider string
	Params   json.RawMessage
}
