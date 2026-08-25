// Package web carries the interface compiled into the binary. Every asset the
// dashboard serves lives here: nothing is fetched from a CDN at runtime.
package web

import "embed"

//go:embed index.html *.css *.js *.png
var Files embed.FS
