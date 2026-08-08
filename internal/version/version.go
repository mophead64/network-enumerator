// Package version holds build metadata set at compile time via -ldflags
// (see build.sh), e.g.:
//
//	-X network-enumerator/internal/version.Version=1.2.3
//	-X network-enumerator/internal/version.BuildDate=2026-08-08T12:00:00Z
//
// `go run`/a plain `go build` without those flags leaves the defaults below
// in place, which is how a local dev build distinguishes itself from a real
// release build.
package version

var (
	Version   = "dev"
	BuildDate = "unknown"
)
