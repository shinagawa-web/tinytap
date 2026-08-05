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

// sysctlPaths are read as informational context for a bug report — see
// docs/capabilities.md's "When cap_syslog is and isn't enough" for how
// nuanced their interaction with capabilities actually is. doctor doesn't
// try to model that interaction; it just surfaces the raw values.
var sysctlPaths = []string{
	"/proc/sys/kernel/perf_event_paranoid",
	"/proc/sys/kernel/unprivileged_bpf_disabled",
}

// checkSysctls reports the raw value of each sysctl in sysctlPaths. root,
// if non-empty, is prepended to each path — tests use this.
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

// checkMemlockRlimit reports RLIMIT_MEMLOCK — informational context only;
// cilium/ebpf's rlimit.RemoveMemlock (called by loader.Load) already
// handles raising it on kernels that need that (see docs/capabilities.md's
// "Why cap_sys_resource turned out not to matter").
func checkMemlockRlimit() Check {
	var rlim unix.Rlimit
	if err := getrlimitFn(unix.RLIMIT_MEMLOCK, &rlim); err != nil {
		return Check{Name: "RLIMIT_MEMLOCK", Severity: Info, Detail: fmt.Sprintf("couldn't read: %v", err)}
	}
	return Check{Name: "RLIMIT_MEMLOCK", Severity: Info, Detail: fmt.Sprintf("soft=%s hard=%s", rlimitString(rlim.Cur), rlimitString(rlim.Max))}
}

// getrlimitFn is injected so tests can force an error without needing a
// real broken rlimit.
var getrlimitFn = unix.Getrlimit

func rlimitString(v uint64) string {
	if v == unix.RLIM_INFINITY {
		return "unlimited"
	}
	return fmt.Sprintf("%d", v)
}

// checkTracepoints confirms every tracepoint loader.Load attaches to
// exists on this kernel (at its primary name, or its fallback if it has
// one). root, if non-empty, overrides the tracing filesystem root — tests
// use this; production callers pass "".
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

// checkArch reports the architecture and which arch-specific objects load
// — informational, but useful bug-report context since the sendfile
// kprobe and TLS uprobes are amd64/arm64-only (everything else degrades
// gracefully on other GOARCH values, see load_kprobe_other.go /
// load_uprobe_other.go).
func checkArch() Check {
	return checkArchFor(runtime.GOARCH)
}

// checkArchFor is checkArch with the GOARCH value injected, so tests can
// exercise the unsupported-architecture branch deterministically instead
// of depending on which arch actually runs the test suite.
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
