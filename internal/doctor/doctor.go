package doctor

type Severity int

const (
	OK Severity = iota
	Info
	Degraded
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

type Check struct {
	Name     string
	Severity Severity
	Detail   string
	Affects  string
	Fix      string
}

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

func AnyBlocking(checks []Check) bool {
	for _, c := range checks {
		if c.Severity == Blocking {
			return true
		}
	}
	return false
}
