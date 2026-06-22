// Package proc looks up process metadata from a /proc-style filesystem.
// All errors (exited process, permission denied, bad format) are treated
// as "unknown" and return "" so callers never need to handle proc errors.
package proc

import (
	"fmt"
	"os"
	"strings"
	"unicode"
)

const defaultRoot = "/proc"

// Lookup returns the process name (comm, up to 15 chars) for the given pid.
//
// root is the /proc mount point; pass "" to use the live "/proc".
// If the process has exited or the comm file cannot be read, Lookup returns "".
func Lookup(root string, pid uint32) string {
	if root == "" {
		root = defaultRoot
	}
	data, err := os.ReadFile(fmt.Sprintf("%s/%d/comm", root, pid))
	if err != nil {
		return ""
	}
	s := strings.TrimRight(string(data), "\n\x00")
	// Reject malformed content: the kernel only writes printable ASCII task names.
	if strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
		return ""
	}
	return s
}

// LookupCmdline returns the full command line for the given pid, with
// arguments space-joined (e.g. "python3 manage.py runserver").
//
// root is the /proc mount point; pass "" to use the live "/proc".
// If the process has exited or the cmdline file cannot be read, LookupCmdline
// returns "". Callers should fall back to Lookup (BPF comm) when it does.
func LookupCmdline(root string, pid uint32) string {
	if root == "" {
		root = defaultRoot
	}
	data, err := os.ReadFile(fmt.Sprintf("%s/%d/cmdline", root, pid))
	if err != nil || len(data) == 0 {
		return ""
	}
	// cmdline is null-terminated args joined by null bytes; replace with spaces.
	return strings.TrimRight(strings.ReplaceAll(string(data), "\x00", " "), " ")
}
