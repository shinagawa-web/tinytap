package doctor

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var libsslLinePattern = regexp.MustCompile(`libssl\.so(\.[0-9]+)*\s+.*=>\s*(\S+)`)

var runLdconfig = func() (string, error) {
	out, err := exec.Command("ldconfig", "-p").Output()
	return string(out), err
}

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
			continue
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
