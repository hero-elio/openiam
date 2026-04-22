// Package httpx is a backwards-compatibility shim around
// openiam/pkg/iam/transport/rest. New callers should use that package
// directly. The shim exists so the SDK refactor can land in stages
// without rewriting every REST handler in one go; it disappears in
// Phase 5.
package httpx

import (
	"net/http"

	rest "openiam/pkg/iam/transport/rest"
)

// DecodeJSON forwards to rest.DecodeJSON.
func DecodeJSON(r *http.Request, dst any) error {
	return rest.DecodeJSON(r, dst)
}
