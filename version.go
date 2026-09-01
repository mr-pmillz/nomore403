// SPDX-License-Identifier: MIT

// Package nomore403 holds build metadata and the payload wordlists that are
// compiled into the nomore403 binary. The command line surface lives in
// internal/cli; the executable entrypoint is cmd/nomore403.
package nomore403

// Populated at build time via -ldflags -X (see Makefile and .goreleaser.yaml).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Version returns the semantic version this binary was built from.
func Version() string {
	return version
}

// BuildInfo returns the version, commit and build date this binary was built
// from.
func BuildInfo() (v, c, d string) {
	return version, commit, date
}
