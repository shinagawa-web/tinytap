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
	fmt.Printf("tinytap %s (commit %s, built %s)\n", version, commit, date)
}
