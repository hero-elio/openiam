package iam

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed authn_test_dist
var authnTestDist embed.FS

func testAuthnPageHandler() http.Handler {
	sub, err := fs.Sub(authnTestDist, "authn_test_dist")
	if err != nil {
		panic("embed authn-test dist: " + err.Error())
	}
	return http.FileServer(http.FS(sub))
}
