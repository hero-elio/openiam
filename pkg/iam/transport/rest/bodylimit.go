package rest

import "net/http"

// DefaultMaxRequestBodyBytes is the per-request body cap applied by
// BodyLimit when no explicit limit is supplied. 1 MiB is generous for
// every JSON request shape we expose (the largest is application
// create with a few short string slices) while still small enough
// that a malicious client can't OOM the process by streaming a large
// body into json.Decode.
const DefaultMaxRequestBodyBytes int64 = 1 << 20 // 1 MiB

// BodyLimit wraps r.Body with http.MaxBytesReader so any subsequent
// json.NewDecoder(r.Body).Decode call returns an error instead of
// happily allocating gigabytes for an attacker-controlled payload.
// The limit is enforced lazily on Read, so GET/DELETE requests with
// no body pay nothing.
//
// Apply once at the API root; downstream handlers don't need to know
// it exists.
func BodyLimit(maxBytes int64) func(http.Handler) http.Handler {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxRequestBodyBytes
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}
