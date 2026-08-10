package doctor

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	minKernelMajor = 5
	minKernelMinor = 8 // BPF_MAP_TYPE_RINGBUF (tinytap's event transport) was added in Linux 5.8
)

var unameFn = unix.Uname

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

func parseKernelVersion(release string) (major, minor int, ok bool) {
	fields := strings.SplitN(release, ".", 3)
	if len(fields) < 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, 0, false
	}
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

func charsToString(b []byte) string {
	i := 0
	for ; i < len(b); i++ {
		if b[i] == 0 {
			break
		}
	}
	return string(b[:i])
}

const btfPath = "/sys/kernel/btf/vmlinux"

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
