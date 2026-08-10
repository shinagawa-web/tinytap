package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/shinagawa-web/tinytap/internal/loader"
)

var sysctlPaths = []string{
	"/proc/sys/kernel/perf_event_paranoid",
	"/proc/sys/kernel/unprivileged_bpf_disabled",
}

func checkSysctls(root string) []Check {
	checks := make([]Check, 0, len(sysctlPaths))
	for _, p := range sysctlPaths {
		path := filepath.Join(root, p)
		name := filepath.Base(p)
		data, err := os.ReadFile(path)
		if err != nil {
			checks = append(checks, Check{Name: name, Severity: Info, Detail: fmt.Sprintf("couldn't read %s: %v", path, err)})
			continue
		}
		checks = append(checks, Check{Name: name, Severity: Info, Detail: strings.TrimSpace(string(data))})
	}
	return checks
}

func checkMemlockRlimit() Check {
	var rlim unix.Rlimit
	if err := getrlimitFn(unix.RLIMIT_MEMLOCK, &rlim); err != nil {
		return Check{Name: "RLIMIT_MEMLOCK", Severity: Info, Detail: fmt.Sprintf("couldn't read: %v", err)}
	}
	return Check{Name: "RLIMIT_MEMLOCK", Severity: Info, Detail: fmt.Sprintf("soft=%s hard=%s", rlimitString(rlim.Cur), rlimitString(rlim.Max))}
}

var getrlimitFn = unix.Getrlimit

func rlimitString(v uint64) string {
	if v == unix.RLIM_INFINITY {
		return "unlimited"
	}
	return fmt.Sprintf("%d", v)
}

func checkTracepoints(root string) Check {
	roots := []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"}
	if root != "" {
		roots = []string{root}
	}

	var missing []string
	for _, tp := range loader.Tracepoints {
		if tracepointExists(roots, tp.Name) {
			continue
		}
		if tp.Fallback != "" && tracepointExists(roots, tp.Fallback) {
			continue
		}
		name := tp.Name
		if tp.Fallback != "" {
			name = fmt.Sprintf("%s (or fallback %s)", tp.Name, tp.Fallback)
		}
		missing = append(missing, name)
	}

	if len(missing) == 0 {
		return Check{Name: "syscall tracepoints", Severity: OK, Detail: fmt.Sprintf("all %d present", len(loader.Tracepoints))}
	}
	return Check{
		Name:     "syscall tracepoints",
		Severity: Blocking,
		Detail:   fmt.Sprintf("missing: %s", strings.Join(missing, ", ")),
		Affects:  "Everything — tinytap can't attach to a tracepoint that doesn't exist on this kernel.",
		Fix:      "confirm CONFIG_FTRACE_SYSCALLS is enabled in this kernel's config",
	}
}

func tracepointExists(roots []string, name string) bool {
	for _, root := range roots {
		if _, err := os.Stat(filepath.Join(root, "events", "syscalls", name, "id")); err == nil {
			return true
		}
	}
	return false
}

func checkArch() Check {
	return checkArchFor(runtime.GOARCH)
}

func checkArchFor(goarch string) Check {
	if goarch == "amd64" || goarch == "arm64" {
		return Check{Name: "architecture", Severity: OK, Detail: fmt.Sprintf("%s (sendfile kprobe + TLS uprobes supported)", goarch)}
	}
	return Check{
		Name:     "architecture",
		Severity: Degraded,
		Detail:   fmt.Sprintf("%s (sendfile kprobe + TLS uprobes not built for this GOARCH)", goarch),
		Affects:  "sendfile payload bytes and all TLS capture. Plaintext HTTP capture via read/write/recvfrom/sendto/etc. is unaffected.",
	}
}
