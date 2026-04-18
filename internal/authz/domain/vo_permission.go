package domain

import (
	"fmt"
	"strings"
)

type Permission struct {
	Resource string
	Action   string
}

func NewPermission(resource, action string) Permission {
	return Permission{Resource: resource, Action: action}
}

func ParsePermission(s string) (Permission, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return Permission{}, fmt.Errorf("invalid permission format: %q (expected resource:action)", s)
	}
	return Permission{Resource: parts[0], Action: parts[1]}, nil
}

func (p Permission) String() string {
	return p.Resource + ":" + p.Action
}

func (p Permission) Matches(resource, action string) bool {
	return (p.Resource == "*" || p.Resource == resource) &&
		(p.Action == "*" || p.Action == action)
}

func (p Permission) IsZero() bool {
	return p.Resource == "" && p.Action == ""
}
