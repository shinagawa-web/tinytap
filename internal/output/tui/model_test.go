package tui

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestFitLeft(t *testing.T) {
	tests := []struct {
		name string
		s    string
		n    int
		want string
	}{
		{"pads short", "GET", 7, "GET    "},
		{"exact fit", "OPTIONS", 7, "OPTIONS"},
		{"keeps exact-width string whole", "containerd-shim", 15, "containerd-shim"},
		{"truncates tail with ellipsis", "containerd-shim-v2", 15, "containerd-shi…"},
		{"empty pads", "", 3, "   "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fitLeft(tt.s, tt.n); got != tt.want {
				t.Errorf("fitLeft(%q, %d) = %q, want %q", tt.s, tt.n, got, tt.want)
			}
			if w := utf8.RuneCountInString(fitLeft(tt.s, tt.n)); w != tt.n {
				t.Errorf("fitLeft(%q, %d) width = %d, want %d", tt.s, tt.n, w, tt.n)
			}
		})
	}
}

func TestFitRight(t *testing.T) {
	tests := []struct {
		s    string
		n    int
		want string
	}{
		{"200", 6, "   200"},
		{"4521", 8, "    4521"},
		{"123456", 6, "123456"},
		{"123456789", 8, "…3456789"}, // overflow: clipped, marked with a leading ellipsis
	}
	for _, tt := range tests {
		if got := fitRight(tt.s, tt.n); got != tt.want {
			t.Errorf("fitRight(%q, %d) = %q, want %q", tt.s, tt.n, got, tt.want)
		}
		if w := utf8.RuneCountInString(fitRight(tt.s, tt.n)); w != tt.n {
			t.Errorf("fitRight(%q, %d) width = %d, want %d", tt.s, tt.n, w, tt.n)
		}
	}
}

// rowLine must stay exactly terminal-width so the table columns line up; the
// path column absorbs the slack and the ellipsis rune still counts as one
// display column.
func TestRowLineWidth(t *testing.T) {
	r := row{
		time:    "19:35:24.123",
		pid:     5950,
		comm:    "curl",
		method:  "GET",
		path:    "/api/v1/users/12345/orders/67890?filter=active&limit=50",
		status:  200,
		bytes:   4521,
		latency: 800 * time.Microsecond,
	}
	const width = 120
	pathWidth := width - fixedWidth - separators
	line := rowLine(r, pathWidth)
	if got := utf8.RuneCountInString(line); got != width {
		t.Errorf("rowLine width = %d, want %d", got, width)
	}
	if !strings.HasSuffix(line, "0.8ms") {
		t.Errorf("rowLine = %q, want it to end with the latency 0.8ms", line)
	}
}
