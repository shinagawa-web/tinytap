package main

import "fmt"

// version, commit, and date are set via -ldflags -X at build time (see the
// Makefile's build target). A plain `go build` leaves them at these
// defaults instead of claiming a false identity.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func printVersion() {
	fmt.Println(versionLine())
}

// versionLine is the single-line build identity string, shared by
// printVersion and `tinytap doctor`'s report header (#209) so a pasted
// bug report carries it either way.
func versionLine() string {
	return fmt.Sprintf("tinytap %s (commit %s, built %s)", version, commit, date)
}
