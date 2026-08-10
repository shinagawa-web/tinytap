package proc

import (
	"fmt"
	"os"
	"strings"
	"unicode"
)

const defaultRoot = "/proc"

func Lookup(root string, pid uint32) string {
	if root == "" {
		root = defaultRoot
	}
	data, err := os.ReadFile(fmt.Sprintf("%s/%d/comm", root, pid))
	if err != nil {
		return ""
	}
	s := strings.TrimRight(string(data), "\n\x00")
	if strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
		return ""
	}
	return s
}

func LookupCmdline(root string, pid uint32) string {
	if root == "" {
		root = defaultRoot
	}
	data, err := os.ReadFile(fmt.Sprintf("%s/%d/cmdline", root, pid))
	if err != nil || len(data) == 0 {
		return ""
	}
	return strings.TrimRight(strings.ReplaceAll(string(data), "\x00", " "), " ")
}
