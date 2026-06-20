package tui

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
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
// marker gutter plus the slack-absorbing path column account for the full
// width, and the ellipsis rune still counts as one display column. The
// selected variant adds ANSI styling, so width is checked on an unselected
// row where the runes map one-to-one to display columns.
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
	pathWidth := width - markerCol - fixedWidth - separators
	line := rowLine(r, pathWidth, false)
	if got := utf8.RuneCountInString(line); got != width {
		t.Errorf("rowLine width = %d, want %d", got, width)
	}
	if !strings.HasPrefix(line, markerBlank) {
		t.Errorf("rowLine = %q, want an unselected row to lead with a blank gutter", line)
	}
	if !strings.HasSuffix(line, "0.8ms") {
		t.Errorf("rowLine = %q, want it to end with the latency 0.8ms", line)
	}
}

// rowLine marks the selected row with the ▸ gutter glyph.
func TestRowLineSelectedMarker(t *testing.T) {
	r := row{time: "19:35:24.123", pid: 5950, comm: "curl", method: "GET", path: "/"}
	pathWidth := 120 - markerCol - fixedWidth - separators
	if got := rowLine(r, pathWidth, true); !strings.Contains(got, markerSelected) {
		t.Errorf("rowLine(selected) = %q, want it to contain the ▸ marker", got)
	}
}

// key feeds a single keystroke through Update and returns the new model.
func key(m model, s string) model {
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)})
	return next.(model)
}

// withRows seeds a model with n placeholder rows in follow mode, as if they
// had streamed in from the capture loop.
func withRows(n int) model {
	m := newModel(120, 24)
	for i := 0; i < n; i++ {
		next, _ := m.Update(rowMsg(row{path: "/"}))
		m = next.(model)
	}
	return m
}

// New rows pin the selection to the newest row while following.
func TestFollowPinsSelectionToNewest(t *testing.T) {
	m := withRows(5)
	if !m.follow {
		t.Fatal("expected follow mode after streaming rows")
	}
	if m.selected != 4 {
		t.Errorf("selected = %d, want 4 (newest)", m.selected)
	}
}

// Moving up pauses follow; new rows then stop stealing the selection.
func TestUpPausesFollow(t *testing.T) {
	m := key(withRows(5), "k") // up from row 4 → row 3
	if m.follow {
		t.Error("up should pause follow")
	}
	if m.selected != 3 {
		t.Errorf("selected = %d, want 3", m.selected)
	}
	next, _ := m.Update(rowMsg(row{path: "/new"}))
	m = next.(model)
	if m.selected != 3 {
		t.Errorf("after a new row, selected = %d, want it to stay at 3", m.selected)
	}
	if len(m.rows) != 6 {
		t.Errorf("rows = %d, want 6", len(m.rows))
	}
}

// Reaching the bottom again re-arms follow.
func TestDownReArmsFollowAtBottom(t *testing.T) {
	m := key(withRows(3), "g") // jump to top, follow off
	if m.follow || m.selected != 0 {
		t.Fatalf("after g: selected=%d follow=%v, want 0/false", m.selected, m.follow)
	}
	m = key(m, "j")
	m = key(m, "j") // back to the newest row
	if m.selected != 2 {
		t.Errorf("selected = %d, want 2", m.selected)
	}
	if !m.follow {
		t.Error("returning to the bottom should re-arm follow")
	}
}

// g/G jump to the first/last row and set follow accordingly.
func TestJumpKeys(t *testing.T) {
	m := key(withRows(10), "g")
	if m.selected != 0 || m.follow {
		t.Errorf("g: selected=%d follow=%v, want 0/false", m.selected, m.follow)
	}
	m = key(m, "G")
	if m.selected != 9 || !m.follow {
		t.Errorf("G: selected=%d follow=%v, want 9/true", m.selected, m.follow)
	}
}

// When the selection moves above the visible window, View pans up so the
// selected row stays on screen (and still carries the ▸ marker).
func TestViewportPansToSelection(t *testing.T) {
	// 24 rows tall → 19 visible; 50 rows means the tail window starts well
	// below row 0, so jumping to the top must scroll the viewport up.
	m := key(withRows(50), "g")
	out := m.View()
	if !strings.Contains(out, markerSelected) {
		t.Fatalf("selected row scrolled off screen: View() = \n%s", out)
	}
	// The newest row's latency-less placeholder isn't distinctive, so assert
	// the marker sits on the first data line (row 0) after the header chrome.
	lines := strings.Split(out, "\n")
	var markerLine int = -1
	for i, ln := range lines {
		if strings.Contains(ln, markerSelected) {
			markerLine = i
			break
		}
	}
	if markerLine == -1 {
		t.Fatal("no ▸ marker found in View output")
	}
}

// View must never emit more lines than the terminal is tall, at any scroll
// position — overflow makes the alt-screen scroll and pushes the header off
// the top. Regression for the g-to-top-with-a-full-buffer case.
func TestViewFitsHeightAtEveryScrollPosition(t *testing.T) {
	const h = 24
	m := newModel(120, h)
	for i := 0; i < 100; i++ {
		next, _ := m.Update(rowMsg(row{path: "/"}))
		m = next.(model)
	}
	for _, k := range []string{"G", "g", "k", "j", "G", "g"} {
		m = key(m, k)
		if got := len(strings.Split(m.View(), "\n")); got > h {
			t.Errorf("after %q: View() emitted %d lines, want <= %d", k, got, h)
		}
	}
}

// The selection clamps at the ends instead of running off either edge.
func TestSelectionClampsAtEdges(t *testing.T) {
	m := key(withRows(3), "g") // row 0
	m = key(m, "k")            // already at top
	if m.selected != 0 {
		t.Errorf("up at top: selected = %d, want 0", m.selected)
	}
	m = key(m, "G") // row 2 (bottom)
	m = key(m, "j") // already at bottom
	if m.selected != 2 {
		t.Errorf("down at bottom: selected = %d, want 2", m.selected)
	}
}
