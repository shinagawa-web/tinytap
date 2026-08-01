package doctor

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// libsslLinePattern matches an ldconfig -p line naming a libssl shared
// object, e.g. "\tlibssl.so.3 (libc6,AArch64) => /lib/aarch64-linux-gnu/libssl.so.3".
var libsslLinePattern = regexp.MustCompile(`libssl\.so(\.[0-9]+)*\s+.*=>\s*(\S+)`)

// runLdconfig is injected so tests don't need a real ldconfig binary.
var runLdconfig = func() (string, error) {
	out, err := exec.Command("ldconfig", "-p").Output()
	return string(out), err
}

// checkLibSSL reports whether the host's own libssl (as ldconfig -p
// reports it) has its execute bit set — cilium/ebpf's link.OpenExecutable
// requires it, but Debian/Ubuntu ship libssl.so.3 as mode 0644 (see
// ErrLibSSLNotExecutable in internal/loader/load_uprobe.go).
//
// This is necessarily best-effort and host-level only: the authoritative
// check is per-process, at attach time (internal/tls.Find resolves a
// traced process's own libssl through /proc/<pid>/root/..., which may
// point inside a container doctor can't see before that process exists —
// see #216). Not finding a host libssl at all isn't itself a problem; it
// just means this host has nothing to check yet.
func checkLibSSL() Check {
	out, err := runLdconfig()
	if err != nil {
		return Check{Name: "libssl (host)", Severity: Info, Detail: "ldconfig -p unavailable: " + err.Error()}
	}

	paths := parseLdconfigLibSSLPaths(out)
	if len(paths) == 0 {
		return Check{Name: "libssl (host)", Severity: Info, Detail: "not found via ldconfig -p — fine unless this host also runs TLS-terminating processes"}
	}

	var checked []string
	for _, p := range paths {
		info, statErr := os.Stat(p)
		if statErr != nil {
			continue // ldconfig's cache can list a path that's since moved; not doctor's problem to diagnose
		}
		checked = append(checked, p)
		if info.Mode()&0o111 == 0 {
			return Check{
				Name:     "libssl execute bit",
				Severity: Degraded,
				Detail:   p + " not set",
				Affects:  "TLS capture only. Plaintext HTTP capture is unaffected.",
				Fix:      "sudo chmod +x " + p,
			}
		}
	}
	if len(checked) == 0 {
		return Check{Name: "libssl (host)", Severity: Info, Detail: "listed by ldconfig -p but none resolvable on disk: " + strings.Join(paths, ", ")}
	}
	return Check{Name: "libssl (host)", Severity: OK, Detail: strings.Join(checked, ", ") + " executable"}
}

// parseLdconfigLibSSLPaths extracts every libssl.so* target path from
// `ldconfig -p` output.
func parseLdconfigLibSSLPaths(output string) []string {
	var paths []string
	for _, line := range strings.Split(output, "\n") {
		m := libsslLinePattern.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		paths = append(paths, m[2])
	}
	return paths
}
