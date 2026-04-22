// Package adminpage embeds the OpenIAM Admin SPA shipped with the SDK.
// It is mounted under /__admin by Engine.Handler so operators can drive
// the full management surface without standing up a separate frontend.
//
// The package lives under pkg/iam/internal so it stays an
// implementation detail; SDK consumers should not import it directly.
package adminpage

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed admin_dist
var dist embed.FS

// Handler returns an http.Handler that serves the embedded SPA. It
// performs an SPA-style fallback: any request whose path does not
// match a file in the bundle (and does not look like an asset request
// containing an extension under /assets/) is rewritten to index.html
// so client-side routing works on hard reloads / deep links.
//
// The handler does not strip any path prefix; mount it under
// http.StripPrefix when serving from a non-root URL (e.g.
// http.StripPrefix("/__admin", adminpage.Handler())).
func Handler() http.Handler {
	sub, err := fs.Sub(dist, "admin_dist")
	if err != nil {
		panic("embed admin dist: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(sub))

	indexBytes, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		panic("embed admin index.html: " + err.Error())
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			serveIndex(w, indexBytes)
			return
		}
		if _, err := fs.Stat(sub, path); err == nil {
			fileServer.ServeHTTP(w, r)
			return
		}
		serveIndex(w, indexBytes)
	})
}

func serveIndex(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(body)
}
