package httpx_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openiam/pkg/httpx"
)

type sample struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

func newReq(body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
}

func TestDecodeJSON_Valid(t *testing.T) {
	var got sample
	if err := httpx.DecodeJSON(newReq(`{"name":"alice","age":30}`), &got); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name != "alice" || got.Age != 30 {
		t.Fatalf("unexpected payload: %+v", got)
	}
}

func TestDecodeJSON_RejectsUnknownFields(t *testing.T) {
	var got sample
	err := httpx.DecodeJSON(newReq(`{"name":"alice","extra":"oops"}`), &got)
	if err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
	if !strings.Contains(err.Error(), "extra") {
		t.Fatalf("expected error to name the unknown field, got %v", err)
	}
	// We must not let the raw "json: " prefix leak to the client.
	if strings.Contains(err.Error(), "json:") {
		t.Fatalf("error should not expose internal json prefix, got %v", err)
	}
}

func TestDecodeJSON_RejectsTrailingJSON(t *testing.T) {
	var got sample
	err := httpx.DecodeJSON(newReq(`{"name":"alice"}{"name":"bob"}`), &got)
	if err == nil {
		t.Fatal("expected error for multiple JSON values, got nil")
	}
	if !strings.Contains(err.Error(), "single JSON") {
		t.Fatalf("expected single-object error, got %v", err)
	}
}

func TestDecodeJSON_EmptyBody(t *testing.T) {
	var got sample
	err := httpx.DecodeJSON(newReq(``), &got)
	if err == nil {
		t.Fatal("expected error for empty body, got nil")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected empty-body message, got %v", err)
	}
}

func TestDecodeJSON_MalformedJSON(t *testing.T) {
	var got sample
	err := httpx.DecodeJSON(newReq(`{`), &got)
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
	// Either "syntax" (unexpected EOF mid-object) or "ended unexpectedly"
	// is acceptable — both communicate the right thing to the client.
	if !strings.Contains(err.Error(), "syntax") && !strings.Contains(err.Error(), "ended") {
		t.Fatalf("expected syntax/ended-unexpectedly message, got %v", err)
	}
}

func TestDecodeJSON_TypeMismatchNamesField(t *testing.T) {
	var got sample
	err := httpx.DecodeJSON(newReq(`{"name":"alice","age":"old"}`), &got)
	if err == nil {
		t.Fatal("expected error for type mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "age") {
		t.Fatalf("expected error to name the offending field, got %v", err)
	}
}

func TestDecodeJSON_NilRequest(t *testing.T) {
	var got sample
	if err := httpx.DecodeJSON(nil, &got); err == nil {
		t.Fatal("expected error for nil request, got nil")
	}
}

func TestDecodeJSON_NilBody(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Body = nil
	var got sample
	if err := httpx.DecodeJSON(r, &got); err == nil {
		t.Fatal("expected error for nil body, got nil")
	}
}

func TestDecodeJSON_BodyLimitTriggersTooLargeMessage(t *testing.T) {
	// Simulate the BodyLimit middleware by wrapping the body with
	// http.MaxBytesReader; DecodeJSON should surface the cap as a
	// clean "too large" message.
	r := httptest.NewRequest(http.MethodPost, "/", io.NopCloser(bytes.NewReader([]byte(`{"name":"`+strings.Repeat("a", 256)+`"}`))))
	rr := httptest.NewRecorder()
	r.Body = http.MaxBytesReader(rr, r.Body, 16)

	var got sample
	err := httpx.DecodeJSON(r, &got)
	if err == nil {
		t.Fatal("expected error for oversized body, got nil")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected too-large message, got %v", err)
	}
}
