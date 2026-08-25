package api

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"strings"
	"sync"

	"endlessh-dashboard/web"
)

const (
	indexFile      = "index.html"
	etagHexLength  = 16
	assetCacheRule = "no-cache"
)

// assetETags maps each embedded file to a hash of its own contents. Deriving the
// tag from the file rather than from the build version is what makes
// revalidation correct: two different assets must never share a tag, or a
// browser holding one of them cached will be told "not modified" for the other
// and keep serving stale bytes.
var assetETags = sync.OnceValue(func() map[string]string {
	tags := map[string]string{}
	fs.WalkDir(web.Files, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		contents, readErr := web.Files.ReadFile(path)
		if readErr != nil {
			return nil
		}
		sum := sha256.Sum256(contents)
		tags[path] = `"` + hex.EncodeToString(sum[:])[:etagHexLength] + `"`
		return nil
	})
	return tags
})

// staticHandler serves the frontend compiled into the binary. Nothing is
// fetched from the network at runtime — that is the whole point of embedding it.
func (s *Server) staticHandler() http.Handler {
	assets := http.FileServerFS(web.Files)

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/api/") {
			writeError(writer, http.StatusNotFound, "no such endpoint")
			return
		}

		requested := strings.TrimPrefix(request.URL.Path, "/")
		if requested == "" {
			s.serveIndex(writer, request)
			return
		}
		if _, err := fs.Stat(web.Files, requested); err != nil {
			// Unknown paths fall back to the app shell so a deep link still loads.
			s.serveIndex(writer, request)
			return
		}

		writer.Header().Set("Cache-Control", assetCacheRule)
		if tag, ok := assetETags()[requested]; ok {
			writer.Header().Set("ETag", tag)
		}
		assets.ServeHTTP(writer, request)
	})
}

func (s *Server) serveIndex(writer http.ResponseWriter, request *http.Request) {
	contents, err := web.Files.ReadFile(indexFile)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "the interface is missing from this build")
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)
	writer.Write(contents)
}
