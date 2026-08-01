// Package doctor runs read-only preflight checks that classify why
// tinytap might not start, or might start with reduced capability, on a
// machine that isn't the primary dev VM (#209). Every check is best-effort
// and safe to run without privileges — the case doctor exists for is
// exactly the one where tinytap can't run yet.
package doctor

// Severity classifies what a failed Check actually costs the caller.
type Severity int

const (
	// OK means the check passed; tinytap is unaffected.
	OK Severity = iota
	// Info is neither pass nor fail — context worth including in a bug
	// report (kernel version, architecture, sysctl values) but not
	// something to act on by itself.
	Info
	// Degraded means tinytap runs, but one specific capability is lost
	// (e.g. no TLS capture). Must never read like a startup failure.
	Degraded
	// Blocking means tinytap cannot run at all until this is fixed.
	Blocking
)

func (s Severity) String() string {
	switch s {
	case OK:
		return "OK"
	case Info:
		return "INFO"
	case Degraded:
		return "DEGRADED"
	case Blocking:
		return "BLOCKING"
	default:
		return "UNKNOWN"
	}
}

// Check is one preflight result.
type Check struct {
	Name     string
	Severity Severity
	Detail   string // e.g. "6.17.0 (>= 5.8 required)" or "not set"
	// Affects and Fix are set only for Degraded/Blocking results — Affects
	// names what specifically stops working (never the whole program, for
	// a Degraded check), Fix is the exact command to run.
	Affects string
	Fix     string
}

// Run executes every preflight check and returns the results in a fixed,
// stable order (kernel, capabilities, sysctls/rlimits, tracepoints,
// architecture, a dry-run BPF load, host libssl).
func Run() []Check {
	var checks []Check
	checks = append(checks, checkKernelVersion(""))
	checks = append(checks, checkBTF(""))
	checks = append(checks, checkCapabilities("")...)
	checks = append(checks, checkSysctls("")...)
	checks = append(checks, checkMemlockRlimit())
	checks = append(checks, checkTracepoints(""))
	checks = append(checks, checkArch())
	checks = append(checks, checkDryRunLoad())
	checks = append(checks, checkLibSSL())
	return checks
}

// AnyBlocking reports whether any check in checks is Blocking severity.
func AnyBlocking(checks []Check) bool {
	for _, c := range checks {
		if c.Severity == Blocking {
			return true
		}
	}
	return false
}
