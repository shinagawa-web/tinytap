package doctor

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Linux capability bit numbers (stable ABI, from <linux/capability.h>).
// golang.org/x/sys/unix doesn't export these as named constants.
const (
	capDACReadSearch = 2
	capSysAdmin      = 21
	capSyslog        = 34
	capPerfmon       = 38
	capBPF           = 39
)

const defaultStatusPath = "/proc/self/status"

// currentGOARCH is runtime.GOARCH, injected so tests can exercise both the
// amd64 and non-amd64 branches of the cap_syslog gate below regardless of
// which architecture actually runs the test.
var currentGOARCH = runtime.GOARCH

// capability describes one entry in the docs site's Running Without Full
// Root page's capability table.
type capability struct {
	name     string
	bit      uint
	severity Severity // Blocking if missing entirely blocks startup, else Degraded
	affects  string
	// amd64Only, if true, means this capability only matters on that one
	// architecture (cap_syslog: the x86_64 sendfile kprobe's kallsyms read).
	amd64Only bool
}

var capabilities = []capability{
	{name: "cap_dac_read_search", bit: capDACReadSearch, severity: Blocking,
		affects: "Everything — needed to open /sys/kernel/tracing/events/syscalls/*/id to resolve tracepoint IDs."},
	{name: "cap_perfmon", bit: capPerfmon, severity: Blocking,
		affects: "Everything — needed to attach the tracepoint/kprobe/fentry programs."},
	{name: "cap_bpf", bit: capBPF, severity: Blocking,
		affects: "Everything — needed to load BPF programs and maps."},
	{name: "cap_sys_admin", bit: capSysAdmin, severity: Degraded,
		affects: "TLS capture only. Plaintext HTTP capture is unaffected."},
	{name: "cap_syslog", bit: capSyslog, severity: Degraded, amd64Only: true,
		affects: "x86_64 sendfile payload capture only (reads /proc/kallsyms). sendfile transfers still pair correctly, just without body content."},
}

// checkCapabilities reports one Check per capability in the capabilities
// table above, read from the running process's effective capability set.
// statusPath, if non-empty, overrides /proc/self/status — tests use this.
func checkCapabilities(statusPath string) []Check {
	if statusPath == "" {
		statusPath = defaultStatusPath
	}

	effective, err := readCapEff(statusPath)
	if err != nil {
		return []Check{{Name: "capabilities", Severity: Info, Detail: fmt.Sprintf("couldn't read %s: %v", statusPath, err)}}
	}

	checks := make([]Check, 0, len(capabilities))
	for _, c := range capabilities {
		if c.amd64Only && currentGOARCH != "amd64" {
			checks = append(checks, Check{Name: c.name, Severity: OK, Detail: "not needed on " + currentGOARCH})
			continue
		}
		if effective&(uint64(1)<<c.bit) != 0 {
			checks = append(checks, Check{Name: c.name, Severity: OK, Detail: "present"})
			continue
		}
		checks = append(checks, Check{
			Name:     c.name,
			Severity: c.severity,
			Detail:   "missing",
			Affects:  c.affects,
			Fix:      setcapFix(c.name),
		})
	}
	return checks
}

// setcapFix returns the exact setcap invocation to grant name alongside the
// full documented set (see the docs site's Running Without Full Root page).
func setcapFix(name string) string {
	return fmt.Sprintf("sudo setcap cap_dac_read_search,cap_perfmon,cap_bpf,cap_sys_admin,cap_syslog=eip <path-to-tinytap>   # adds %s", name)
}

// readCapEff parses the CapEff line out of a /proc/<pid>/status-formatted
// file and returns it as a capability bitmask.
func readCapEff(statusPath string) (uint64, error) {
	f, err := os.Open(statusPath)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		hex := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		v, err := strconv.ParseUint(hex, 16, 64)
		if err != nil {
			return 0, fmt.Errorf("parse CapEff %q: %w", hex, err)
		}
		return v, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("no CapEff line in %s", statusPath)
}
