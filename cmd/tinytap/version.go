package main

import "fmt"

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func printVersion() {
	fmt.Println(versionLine())
}

func versionLine() string {
	return fmt.Sprintf("tinytap %s (commit %s, built %s)", version, commit, date)
}
