// Package testpage embeds the static authn smoke-test single-page app
// shipped with the SDK. It is mounted under /__test/authn by
// Engine.Handler when the Authn module is configured, so developers
// can register / login / refresh against a fresh deployment without
// pulling in a separate frontend.
//
// The package lives under pkg/iam/internal so it stays an
// implementation detail; SDK consumers should not import it directly.
package testpage

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed authn_test_dist
var dist embed.FS

// Handler returns an http.Handler that serves the embedded SPA. The
// handler does not strip any path prefix; mount it under
// http.StripPrefix when serving from a non-root URL.
func Handler() http.Handler {
	sub, err := fs.Sub(dist, "authn_test_dist")
	if err != nil {
		panic("embed authn-test dist: " + err.Error())
	}
	return http.FileServer(http.FS(sub))
}
