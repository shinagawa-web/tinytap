// Package proc looks up process metadata from a /proc-style filesystem.
// It reads /proc/<pid>/comm to resolve a PID to its process name.
// All errors (exited process, permission denied, bad format) are treated
// as "unknown" and return "" so callers never need to handle proc errors.
package proc

import (
	"fmt"
	"os"
	"strings"
)

const defaultRoot = "/proc"

// Lookup returns the process name (comm) for the given pid.
//
// root is the /proc mount point; pass "" to use the live "/proc".
// If the process has exited or the comm file cannot be read for any
// reason, Lookup returns "" — treat "" as "unknown" and continue.
func Lookup(root string, pid uint32) string {
	if root == "" {
		root = defaultRoot
	}
	data, err := os.ReadFile(fmt.Sprintf("%s/%d/comm", root, pid))
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(data), "\n\x00")
}
