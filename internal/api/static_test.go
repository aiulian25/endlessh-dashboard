package api

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"endlessh-dashboard/web"
)

func TestStaticAssetRangeRequests(t *testing.T) {
	// Exercise the toolchain's default Range limit, even if the developer's
	// environment overrides it. All requests stay in memory and need no login.
	t.Setenv("GODEBUG", "")
	asset, err := web.Files.ReadFile("app.js")
	if err != nil {
		t.Fatal(err)
	}
	if len(asset) < 256 {
		t.Fatal("the fixture must be larger than the total requested range bytes")
	}

	tests := []struct {
		name         string
		rangeHeader  string
		status       int
		contentRange string
		body         []byte
	}{
		{name: "whole asset", status: http.StatusOK, body: asset},
		{
			name: "single range", rangeHeader: "bytes=0-9",
			status:       http.StatusPartialContent,
			contentRange: fmt.Sprintf("bytes 0-9/%d", len(asset)), body: asset[:10],
		},
		{
			name: "unsatisfiable range", rangeHeader: fmt.Sprintf("bytes=%d-", len(asset)),
			status:       http.StatusRequestedRangeNotSatisfiable,
			contentRange: fmt.Sprintf("bytes */%d", len(asset)),
		},
		{
			// A small, bounded reproduction of GO-2026-6609: an affected
			// compiler expands these into a multipart response. Patched Go
			// ignores excessive ranges and returns the ordinary whole asset.
			name: "excessive ranges", rangeHeader: "bytes=" + strings.Repeat("0-0,", 255) + "0-0",
			status: http.StatusOK, body: asset,
		},
	}

	handler := (&Server{}).staticHandler()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/app.js", nil)
			if test.rangeHeader != "" {
				request.Header.Set("Range", test.rangeHeader)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
			if got := response.Header().Get("Content-Range"); got != test.contentRange {
				t.Errorf("Content-Range = %q, want %q", got, test.contentRange)
			}
			if test.body != nil && !bytes.Equal(response.Body.Bytes(), test.body) {
				t.Error("response body does not match the requested asset bytes")
			}
		})
	}
}

// The browser fixture serves files from disk; verify that the shipped binary's
// static handler serves the new lifecycle dependency rather than the HTML shell.
func TestRequestLifecycleModuleIsServed(t *testing.T) {
	for _, name := range []string{"requests.js", "panel-state.js", "navigation.js", "focus.js"} {
		t.Run(name, func(t *testing.T) {
			expected, err := web.Files.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			(&Server{}).staticHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/"+name, nil))
			if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Content-Type"), "javascript") || !bytes.Equal(response.Body.Bytes(), expected) {
				t.Fatalf("lifecycle module missing from static response: status=%d type=%s", response.Code, response.Header().Get("Content-Type"))
			}
		})
	}
}
