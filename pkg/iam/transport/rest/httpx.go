package rest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// DecodeJSON parses the request body as a single JSON value into dst.
//
// Strictness is the point: unknown fields are rejected (so a typo in a
// client payload surfaces immediately instead of being silently dropped),
// the body must contain exactly one JSON value, and we never gulp the
// whole request into memory beyond what the BodyLimit middleware already
// allows.
//
// Errors are translated into short, user-safe messages — no Go-specific
// jargon ("json: cannot unmarshal …") leaks to the API client. Callers
// should treat any returned error as a 400 invalid_request.
func DecodeJSON(r *http.Request, dst any) error {
	if r == nil || r.Body == nil {
		return errors.New("request body is required")
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		return mapDecodeError(err)
	}
	if dec.More() {
		return errors.New("request body must contain a single JSON object")
	}
	return nil
}

// mapDecodeError converts the various error shapes returned by
// encoding/json (and the body-size limiter) into a single, client-facing
// error. We collapse internal details so handlers can log err.Error()
// straight into the API response without leaking implementation noise.
func mapDecodeError(err error) error {
	var (
		syntaxErr        *json.SyntaxError
		unmarshalTypeErr *json.UnmarshalTypeError
		maxBytesErr      *http.MaxBytesError
	)

	switch {
	case errors.As(err, &syntaxErr):
		return fmt.Errorf("invalid JSON: syntax error at byte %d", syntaxErr.Offset)
	case errors.As(err, &unmarshalTypeErr):
		if unmarshalTypeErr.Field != "" {
			return fmt.Errorf("field %q must be of type %s", unmarshalTypeErr.Field, unmarshalTypeErr.Type)
		}
		return fmt.Errorf("value must be of type %s", unmarshalTypeErr.Type)
	case errors.As(err, &maxBytesErr):
		return errors.New("request body too large")
	case errors.Is(err, io.EOF):
		return errors.New("request body is empty")
	case errors.Is(err, io.ErrUnexpectedEOF):
		return errors.New("request body ended unexpectedly")
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		// The encoding/json package returns a plain *errors.errorString
		// for unknown fields, so we have to match by prefix. Strip the
		// "json: " marker so the field name reaches the client cleanly.
		return errors.New(strings.TrimPrefix(err.Error(), "json: "))
	}
	return errors.New("invalid request body")
}
