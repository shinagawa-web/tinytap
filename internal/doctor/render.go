package doctor

import (
	"fmt"
	"strings"
)

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
