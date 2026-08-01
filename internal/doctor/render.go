package doctor

import (
	"fmt"
	"strings"
)

// Render formats checks as the copy-paste-friendly report `tinytap doctor`
// prints: one line per check plus, for anything Degraded or Blocking, an
// indented Affects/Fix pair, followed by a one-line summary. versionLine is
// prepended as a header (e.g. "tinytap v0.6.1 (commit ..., built ...)") so
// a pasted bug report carries the build identity without a separate
// `tinytap --version` (#205).
func Render(checks []Check, versionLine string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "tinytap doctor — %s\n\n", versionLine)

	var blocking, degraded, ok, info int
	for _, c := range checks {
		fmt.Fprintf(&b, "[%-8s] %-28s %s\n", c.Severity, c.Name, c.Detail)
		if c.Affects != "" {
			fmt.Fprintf(&b, "    Affects: %s\n", c.Affects)
		}
		if c.Fix != "" {
			fmt.Fprintf(&b, "    Fix:     %s\n", c.Fix)
		}
		switch c.Severity {
		case Blocking:
			blocking++
		case Degraded:
			degraded++
		case OK:
			ok++
		default:
			info++
		}
	}

	fmt.Fprintf(&b, "\n%d ok, %d degraded, %d blocking, %d info\n", ok, degraded, blocking, info)
	return b.String()
}
