package doctor

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// minKernelMajor/minKernelMinor is the floor documented in README's
// Requirements: BPF_MAP_TYPE_RINGBUF (tinytap's event transport) was added
// in Linux 5.8.
const (
	minKernelMajor = 5
	minKernelMinor = 8
)

// unameFn is injected so tests can force an error without needing a real
// broken uname(2).
var unameFn = unix.Uname

// checkKernelVersion reports whether the running kernel clears the 5.8
// floor. release, if non-empty, overrides the real uname release string —
// tests use this; production callers pass "".
func checkKernelVersion(release string) Check {
	if release == "" {
		var uts unix.Utsname
		if err := unameFn(&uts); err != nil {
			return Check{Name: "kernel version", Severity: Info, Detail: fmt.Sprintf("uname failed: %v", err)}
		}
		release = charsToString(uts.Release[:])
	}

	major, minor, ok := parseKernelVersion(release)
	if !ok {
		return Check{Name: "kernel version", Severity: Info, Detail: fmt.Sprintf("%s (couldn't parse major.minor)", release)}
	}

	detail := fmt.Sprintf("%s (>= %d.%d required)", release, minKernelMajor, minKernelMinor)
	if major > minKernelMajor || (major == minKernelMajor && minor >= minKernelMinor) {
		return Check{Name: "kernel version", Severity: OK, Detail: detail}
	}
	return Check{
		Name:     "kernel version",
		Severity: Blocking,
		Detail:   detail,
		Affects:  "Everything — BPF_MAP_TYPE_RINGBUF (tinytap's event transport) doesn't exist below 5.8.",
		Fix:      "upgrade the kernel to 5.8 or later",
	}
}

// parseKernelVersion extracts the leading major.minor from a uname release
// string like "6.17.0-41-generic" or "5.8.0".
func parseKernelVersion(release string) (major, minor int, ok bool) {
	fields := strings.SplitN(release, ".", 3)
	if len(fields) < 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, 0, false
	}
	// The minor field may have a trailing patch/suffix (e.g. "17" in
	// "6.17.0-41-generic" is clean, but be defensive against "17-rc1"-style
	// strings anyway).
	minorField := fields[1]
	for i, r := range minorField {
		if r < '0' || r > '9' {
			minorField = minorField[:i]
			break
		}
	}
	minor, err = strconv.Atoi(minorField)
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

// charsToString converts a NUL-terminated [n]byte (as used by
// unix.Utsname's fields) into a Go string.
func charsToString(b []byte) string {
	i := 0
	for ; i < len(b); i++ {
		if b[i] == 0 {
			break
		}
	}
	return string(b[:i])
}

// btfPath is the standard location for the running kernel's BTF blob.
const btfPath = "/sys/kernel/btf/vmlinux"

// checkBTF reports whether kernel BTF is available — required for the
// fentry/tcp_sendmsg_locked kprobe that captures sendfile payload bytes
// (internal/loader/load_kprobe.go). Its absence degrades that one
// capability; everything else about tinytap is unaffected. path, if
// non-empty, overrides btfPath — tests use this.
func checkBTF(path string) Check {
	if path == "" {
		path = btfPath
	}
	if _, err := os.Stat(path); err == nil {
		return Check{Name: "kernel BTF", Severity: OK, Detail: path + " present"}
	}
	return Check{
		Name:     "kernel BTF",
		Severity: Degraded,
		Detail:   path + " not present",
		Affects:  "sendfile payload bytes only. sendfile transfers still pair correctly, just without body content.",
		Fix:      "install your distro's kernel debug/BTF package, or use a kernel built with CONFIG_DEBUG_INFO_BTF=y",
	}
}
