package domain

import (
	"net/mail"
	"strings"
)

type Email struct {
	value string
}

func NewEmail(raw string) (Email, error) {
	trimmed := strings.TrimSpace(raw)
	addr, err := mail.ParseAddress(trimmed)
	if err != nil {
		return Email{}, ErrInvalidEmail
	}
	return Email{value: strings.ToLower(addr.Address)}, nil
}

func NewEmailFromTrusted(value string) Email {
	return Email{value: value}
}

func (e Email) String() string      { return e.value }
func (e Email) Equals(o Email) bool { return e.value == o.value }
func (e Email) IsEmpty() bool       { return e.value == "" }
