// Package web embeds the static frontend into the compiled binary so the
// whole tool — server and UI — ships as one file with no external assets to
// manage, and nothing to fetch from the internet at runtime.
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed index.html static
var files embed.FS

func Handler() http.Handler {
	sub, err := fs.Sub(files, ".")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}
