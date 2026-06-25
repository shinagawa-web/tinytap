package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/shinagawa-web/tinytap/internal/protocols/http"
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
	line := rowLine(r, pathWidth, false, false)
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

// latencyStr never overflows the 7-column ms budget: the sub-second form is
// capped at 999.9ms, and at exactly 1s it rolls over to seconds.
func TestLatencyStr(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{800 * time.Microsecond, "0.8ms"},
		{12500 * time.Microsecond, "12.5ms"},
		{999900 * time.Microsecond, "999.9ms"},
		{999950 * time.Microsecond, "999.9ms"}, // would round to 1000.0ms without the cap
		{time.Second, "1.0s"},
		{1500 * time.Millisecond, "1.5s"},
		{10 * time.Second, "10.0s"},
	}
	for _, tc := range tests {
		if got := latencyStr(tc.d); got != tc.want {
			t.Errorf("latencyStr(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

// Second-scale latencies (>= 1s) are highlighted; sub-second ones are not, and
// the zero-width color escapes must not change the row's visible width.
func TestRowLineSlowLatencyHighlighted(t *testing.T) {
	// go test's stdout isn't a TTY, so lipgloss defaults to the no-color
	// profile and Render would be a silent no-op. Force a profile that emits
	// ANSI so the styling is observable, and restore it afterwards.
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.ANSI)
	t.Cleanup(func() { lipgloss.SetColorProfile(prev) })

	const width = 120
	pathWidth := width - markerCol - fixedWidth - separators
	slow := rowLine(row{path: "/", latency: 1500 * time.Millisecond}, pathWidth, false, false)
	fast := rowLine(row{path: "/", latency: 800 * time.Microsecond}, pathWidth, false, false)

	// The slow row carries styling around its "1.5s" value; the fast one stays
	// plain. \x1b[ is the start of any ANSI escape sequence.
	if !strings.Contains(slow, "1.5s") || !strings.Contains(slow, "\x1b[") {
		t.Errorf("slow row (>=1s) should show a styled 1.5s, got %q", slow)
	}
	if strings.Contains(fast, "\x1b[") {
		t.Errorf("sub-second row should be unstyled, got %q", fast)
	}
	// lipgloss.Width ignores the escapes: the styled row must still occupy
	// exactly `width` display columns so the table stays aligned.
	if got := lipgloss.Width(slow); got != width {
		t.Errorf("slow row visible width = %d, want %d", got, width)
	}
}

// rowLine marks the selected row with the ▸ gutter glyph.
func TestRowLineSelectedMarker(t *testing.T) {
	r := row{time: "19:35:24.123", pid: 5950, comm: "curl", method: "GET", path: "/"}
	pathWidth := 120 - markerCol - fixedWidth - separators
	if got := rowLine(r, pathWidth, true, true); !strings.Contains(got, markerSelected) {
		t.Errorf("rowLine(selected) = %q, want it to contain the ▸ marker", got)
	}
}

// The numeric column headers are right-aligned so they sit over their
// right-aligned values (BYTES used to drift left of the digits).
func TestHeaderNumericColumnsRightAligned(t *testing.T) {
	const width = 120
	pathWidth := width - markerCol - fixedWidth - separators
	want := markerBlank + strings.Join([]string{
		fitLeft("TIME", colTime),
		fitLeft("PID", colPID),
		fitLeft("COMM", colComm),
		fitLeft("METHOD", colMethod),
		fitLeft("PATH", pathWidth),
		fitRight("STATUS", colStatus),
		fitRight("BYTES", colBytes),
		fitRight("LATENCY", colLatency),
	}, " ")
	got := headerLine(pathWidth)
	if got != want {
		t.Errorf("headerLine mismatch\n got: %q\nwant: %q", got, want)
	}
	// The BYTES label's right edge must line up with a value's right edge.
	r := row{bytes: 1253}
	rl := rowLine(r, pathWidth, false, false)
	if hi, ri := strings.Index(got, "BYTES")+len("BYTES"), strings.Index(rl, "1253")+len("1253"); hi != ri {
		t.Errorf("BYTES header ends at col %d but value ends at col %d", hi, ri)
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
	markerLine := -1
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

// After jumping to the top, moving down advances the cursor within the
// visible window first; the content only scrolls once the cursor reaches the
// last visible row. (Regression: the cursor used to stick to the top row
// while the rows scrolled under it.)
func TestDownMovesCursorBeforeScrolling(t *testing.T) {
	const h = 24
	m := newModel(120, h)
	for i := 0; i < 100; i++ {
		next, _ := m.Update(rowMsg(row{path: "/"}))
		m = next.(model)
	}
	m = key(m, "g") // top: selected=0, top=0
	if m.top != 0 || m.selected != 0 {
		t.Fatalf("after g: selected=%d top=%d, want 0/0", m.selected, m.top)
	}
	visible := m.visibleRows()
	// Step down to the last visible row — top must not move yet.
	for i := 1; i < visible; i++ {
		m = key(m, "j")
		if m.selected != i {
			t.Fatalf("after %d×j: selected=%d, want %d", i, m.selected, i)
		}
		if m.top != 0 {
			t.Errorf("after %d×j: top=%d, want 0 (cursor should move, not the content)", i, m.top)
		}
	}
	// One more down: cursor is at the bottom, so now the content scrolls.
	m = key(m, "j")
	if m.selected != visible {
		t.Fatalf("selected=%d, want %d", m.selected, visible)
	}
	if m.top != 1 {
		t.Errorf("top=%d, want 1 (content scrolls once the cursor hits the bottom)", m.top)
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

// press feeds a non-rune key (Enter, Esc, …) through Update.
func press(m model, t tea.KeyType) model {
	next, _ := m.Update(tea.KeyMsg{Type: t})
	return next.(model)
}

// Enter opens the detail panel; Enter again closes it.
func TestEnterTogglesDetail(t *testing.T) {
	m := withRows(5)
	if m.detailOpen {
		t.Fatal("panel should start closed")
	}
	m = press(m, tea.KeyEnter)
	if !m.detailOpen {
		t.Error("Enter should open the panel")
	}
	m = press(m, tea.KeyEnter)
	if m.detailOpen {
		t.Error("Enter again should close the panel")
	}
}

// Esc closes an open panel and is a no-op when already closed.
func TestEscClosesDetailOnlyWhenOpen(t *testing.T) {
	m := press(withRows(5), tea.KeyEsc)
	if m.detailOpen {
		t.Error("Esc with the panel closed should stay closed")
	}
	m = press(withRows(5), tea.KeyEnter)
	m = press(m, tea.KeyEsc)
	if m.detailOpen {
		t.Error("Esc should close an open panel")
	}
}

// The detail divider names the selected row and tracks it as the selection
// moves while the panel stays open.
func TestDetailHeaderTracksSelectionLive(t *testing.T) {
	m := withRows(5)
	for i := range m.rows {
		m.rows[i].pid = uint32(1000 + i)
		m.rows[i].comm = fmt.Sprintf("proc%d", i)
	}
	m = press(m, tea.KeyEnter) // open on the newest row (index 4)
	out := m.View()
	if !strings.Contains(out, "───── Detail ─────") {
		t.Errorf("View missing the Detail divider:\n%s", out)
	}
	if !strings.Contains(out, "pid=1004 (proc4)") {
		t.Errorf("divider should name the selected row, got:\n%s", out)
	}
	if !strings.Contains(out, " Request:") || !strings.Contains(out, " Response:") {
		t.Errorf("View should show the Request/Response header sections:\n%s", out)
	}
	// Move the selection up; the divider must update live.
	m = key(m, "k")
	out = m.View()
	if !strings.Contains(out, "pid=1003 (proc3)") {
		t.Errorf("divider should follow the moved selection, got:\n%s", out)
	}
	if strings.Contains(out, "pid=1004 (proc4)") {
		t.Error("divider should no longer name the previous selection")
	}
}

// Opening the panel shrinks the table but it stays navigable, and closing it
// restores the full row budget.
func TestDetailShrinksTableButKeepsItNavigable(t *testing.T) {
	m := withRows(100)
	full := m.visibleRows()
	m = press(m, tea.KeyEnter)
	open := m.visibleRows()
	if open >= full {
		t.Errorf("open visibleRows=%d, want fewer than the full %d", open, full)
	}
	if open <= 0 {
		t.Errorf("open visibleRows=%d, want the table to keep some rows", open)
	}
	// Navigation still moves the selection with the panel open.
	before := m.selected
	m = key(m, "k")
	if m.selected != before-1 {
		t.Errorf("selected=%d, want navigation to move it to %d", m.selected, before-1)
	}
	// Closing restores the full height.
	m = press(m, tea.KeyEsc)
	if got := m.visibleRows(); got != full {
		t.Errorf("after close visibleRows=%d, want the full %d", got, full)
	}
}

// View must still fit the terminal height with the panel open, at any scroll
// position — the table + detail panel + footer share the fixed height.
func TestViewFitsHeightWithDetailOpen(t *testing.T) {
	const h = 24
	m := newModel(120, h)
	for i := 0; i < 100; i++ {
		next, _ := m.Update(rowMsg(row{path: "/"}))
		m = next.(model)
	}
	m = press(m, tea.KeyEnter)
	for _, k := range []string{"G", "g", "k", "j", "G"} {
		m = key(m, k)
		if got := len(strings.Split(m.View(), "\n")); got != h {
			t.Errorf("after %q with the panel open: View() emitted %d lines, want %d", k, got, h)
		}
	}
}

// appendRow streams one fully-populated row into the model, as the capture
// loop would, and returns the updated model.
func appendRow(m model, r row) model {
	next, _ := m.Update(rowMsg(r))
	return next.(model)
}

// The detail panel shows the request and response start lines followed by
// their headers, and the headers keep their on-wire order.
func TestDetailRendersHeadersInWireOrder(t *testing.T) {
	m := newModel(120, 60) // tall enough that every header line fits the panel
	m = appendRow(m, row{
		method: "GET", path: "/api", reqVersion: "HTTP/1.1",
		status: 200, resVersion: "HTTP/1.1", reason: "OK",
		reqHeaders: []http.Header{
			{Name: "Host", Value: "localhost:8081"},
			{Name: "User-Agent", Value: "curl/8.14.1"},
			{Name: "Accept", Value: "*/*"},
		},
		resHeaders: []http.Header{
			{Name: "Content-Type", Value: "application/json"},
			{Name: "Content-Length", Value: "12"},
		},
	})
	m.detailOpen = true
	body := strings.Join(m.detailBody(), "\n")

	for _, want := range []string{
		" Request:", "GET /api HTTP/1.1",
		"Host: localhost:8081", "User-Agent: curl/8.14.1", "Accept: */*",
		" Response:", "HTTP/1.1 200 OK",
		"Content-Type: application/json", "Content-Length: 12",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("detail body missing %q:\n%s", want, body)
		}
	}

	// Wire order: Host before User-Agent before Accept.
	if i, j := strings.Index(body, "Host:"), strings.Index(body, "User-Agent:"); i > j {
		t.Errorf("Host should precede User-Agent (wire order):\n%s", body)
	}
	if i, j := strings.Index(body, "User-Agent:"), strings.Index(body, "Accept:"); i > j {
		t.Errorf("User-Agent should precede Accept (wire order):\n%s", body)
	}
	// The Request section precedes the Response section.
	if i, j := strings.Index(body, " Request:"), strings.Index(body, " Response:"); i > j {
		t.Errorf("Request section should precede Response:\n%s", body)
	}
}

// A header section with no headers renders an explicit "(none)" rather than a
// blank gap, so a capture that genuinely had no headers reads as such.
func TestDetailHeaderSectionShowsNoneWhenEmpty(t *testing.T) {
	m := newModel(120, 60)
	m = appendRow(m, row{
		method: "GET", path: "/", reqVersion: "HTTP/1.1",
		status: 204, resVersion: "HTTP/1.1", reason: "No Content",
	})
	m.detailOpen = true
	body := strings.Join(m.detailBody(), "\n")
	if got := strings.Count(body, "(none)"); got != 2 {
		t.Errorf("want (none) for both empty header sections, got %d:\n%s", got, body)
	}
}

// The body is clipped to the panel's fixed height and width: a long or numerous
// header set must not wrap or overflow, and hidden lines are flagged.
func TestDetailBodyClipsToPanelHeightAndWidth(t *testing.T) {
	m := newModel(120, 24)
	hdrs := make([]http.Header, 40)
	for i := range hdrs {
		hdrs[i] = http.Header{Name: fmt.Sprintf("X-Header-%02d", i), Value: strings.Repeat("v", 300)}
	}
	m = appendRow(m, row{
		method: "GET", path: "/", reqVersion: "HTTP/1.1",
		status: 200, resVersion: "HTTP/1.1", reason: "OK", reqHeaders: hdrs,
	})
	m.detailOpen = true
	body := m.detailBody()

	if len(body) != m.bodyLines() {
		t.Errorf("detailBody returned %d lines, want bodyLines()=%d", len(body), m.bodyLines())
	}
	for i, line := range body {
		if w := utf8.RuneCountInString(line); w > m.width {
			t.Errorf("line %d width %d exceeds m.width %d: %q", i, w, m.width, line)
		}
	}
	// At rest (offset 0) the overflow is below, flagged by a down indicator; the
	// top has nothing hidden above it, so no up indicator yet.
	joined := strings.Join(body, "\n")
	if !strings.Contains(joined, "↓") {
		t.Errorf("overflowing headers should flag the hidden lines with a ↓ indicator:\n%s", joined)
	}
	if strings.Contains(joined, "↑") {
		t.Errorf("at the top there is nothing above, so no ↑ indicator:\n%s", joined)
	}
}

// Even below the startup size floor (reachable only via a runtime resize, #57),
// an open detail panel must leave at least one table row — visibleRows() can
// never collapse to 0 — and View must still fit the terminal height exactly.
func TestDetailKeepsOneTableRowAtAnyHeight(t *testing.T) {
	for h := chromeLines + 1; h <= 24; h++ {
		m := newModel(120, h)
		m = appendRow(m, row{
			method: "GET", path: "/", reqVersion: "HTTP/1.1",
			status: 200, resVersion: "HTTP/1.1", reason: "OK",
		})
		m.detailOpen = true
		if got := m.visibleRows(); got < 1 {
			t.Errorf("height=%d: visibleRows()=%d with the panel open, want >= 1", h, got)
		}
		if got := len(strings.Split(m.View(), "\n")); got != h {
			t.Errorf("height=%d: View() emitted %d lines, want %d", h, got, h)
		}
	}
}

// A POST renders both a request and a response body block.
func TestDetailRendersBothBodiesForPost(t *testing.T) {
	r := row{
		method: "POST", path: "/u", reqVersion: "HTTP/1.1",
		status: 201, resVersion: "HTTP/1.1", reason: "Created",
		reqBytes: 5, bytes: 4,
		reqBody: []byte("hello"), resBody: []byte("done"),
	}
	got := strings.Join(detailContent(r, false), "\n")
	if !strings.Contains(got, "Request body (decoded, 5/5 bytes):") || !strings.Contains(got, "   hello") {
		t.Errorf("missing request body block:\n%s", got)
	}
	if !strings.Contains(got, "Response body (decoded, 4/4 bytes):") || !strings.Contains(got, "   done") {
		t.Errorf("missing response body block:\n%s", got)
	}
}

// A GET has no request body, so that block is omitted entirely (no "(none)").
func TestDetailOmitsAbsentRequestBody(t *testing.T) {
	r := row{
		method: "GET", path: "/", reqVersion: "HTTP/1.1",
		status: 200, resVersion: "HTTP/1.1", reason: "OK",
		bytes: 4, resBody: []byte("body"),
	}
	got := strings.Join(detailContent(r, false), "\n")
	if strings.Contains(got, "Request body") {
		t.Errorf("GET has no request body; the block should be omitted:\n%s", got)
	}
	if !strings.Contains(got, "Response body (decoded, 4/4 bytes):") {
		t.Errorf("missing response body block:\n%s", got)
	}
}

// A truncated body is flagged in the block header with kept/total bytes.
func TestDetailBodyShowsTruncatedMarker(t *testing.T) {
	r := row{
		method: "GET", path: "/", status: 200, bytes: 1000,
		resBody: make([]byte, 256), resBodyTruncated: true,
	}
	got := strings.Join(detailContent(r, false), "\n")
	if !strings.Contains(got, "Response body (decoded, 256/1000 bytes — truncated):") {
		t.Errorf("want a truncated marker with kept/total bytes:\n%s", got)
	}
}

// Binary content: hex shows the raw bytes and an ASCII gutter; decoded shows
// non-printable bytes as '.'.
func TestBodyHexAndDecodedViews(t *testing.T) {
	body := []byte{0x7b, 0x00, 0xff, 0x41} // '{', NUL, 0xff, 'A'
	r := row{method: "GET", path: "/", status: 200, bytes: 4, resBody: body}

	dec := strings.Join(detailContent(r, false), "\n")
	if !strings.Contains(dec, "{..A") {
		t.Errorf("decoded should show non-printables as '.':\n%s", dec)
	}

	hexv := strings.Join(detailContent(r, true), "\n")
	if !strings.Contains(hexv, "7b 00 ff 41") {
		t.Errorf("hex should show the raw bytes:\n%s", hexv)
	}
	if !strings.Contains(hexv, "|{..A|") {
		t.Errorf("hex ASCII gutter should show non-printables as '.':\n%s", hexv)
	}
}

// b (and h) toggle every body block between decoded and hex at once, and the
// mode is sticky.
func TestBodyModeToggleKey(t *testing.T) {
	m := newModel(120, 60)
	m = appendRow(m, row{method: "GET", path: "/", status: 200, bytes: 2, resBody: []byte{0x41, 0x00}})
	m.detailOpen = true
	if strings.Contains(m.View(), "(hex,") {
		t.Error("default body mode should be decoded")
	}
	m = key(m, "b")
	if !strings.Contains(m.View(), "(hex,") {
		t.Errorf("b should switch to hex:\n%s", m.View())
	}
	m = key(m, "h")
	if strings.Contains(m.View(), "(hex,") {
		t.Error("h should also toggle, switching back to decoded")
	}
}

// The session body budget bounds total retained body bytes: once exceeded,
// the oldest rows lose their bodies (their summary survives) while the newest
// keep theirs.
func TestSessionBodyBudgetEvictsOldest(t *testing.T) {
	m := newModel(120, 24)
	big := 1024 * 1024 // ~1 MiB per row
	n := sessionBodyBudget/big + 3
	for i := 0; i < n; i++ {
		m = appendRow(m, row{method: "GET", path: "/", status: 200, bytes: big, resBody: make([]byte, big)})
	}
	if m.bodyBytes > sessionBodyBudget {
		t.Errorf("retained body bytes %d exceed budget %d", m.bodyBytes, sessionBodyBudget)
	}
	if len(m.rows[0].resBody) != 0 {
		t.Error("oldest row should have had its body evicted")
	}
	if len(m.rows[len(m.rows)-1].resBody) == 0 {
		t.Error("newest row should still have its body")
	}
}

// A CRLF-delimited text body breaks into lines without spurious '.' at the
// ends (the '\r' is dropped, not rendered as a non-printable).
func TestDecodedBodyDropsCarriageReturns(t *testing.T) {
	r := row{method: "GET", path: "/", status: 200, bytes: 10, resBody: []byte("ab\r\ncd\r\nef")}
	got := strings.Join(detailContent(r, false), "\n")
	if strings.Contains(got, "ab.") || strings.Contains(got, "cd.") {
		t.Errorf("CRLF should not leave a spurious '.' at line ends:\n%s", got)
	}
	for _, want := range []string{"   ab", "   cd", "   ef"} {
		if !strings.Contains(got, want) {
			t.Errorf("CRLF body should break into lines, missing %q:\n%s", want, got)
		}
	}
}

// withScrollablePanel seeds five rows whose detail content overflows the panel
// (40 headers each), opens the panel on the newest row, and returns the model in
// table focus. Scrolling is meaningful because the content exceeds bodyLines().
func withScrollablePanel() model {
	m := newModel(120, 24)
	hdrs := make([]http.Header, 40)
	for i := range hdrs {
		hdrs[i] = http.Header{Name: fmt.Sprintf("X-Header-%02d", i), Value: "v"}
	}
	for i := 0; i < 5; i++ {
		m = appendRow(m, row{
			method: "GET", path: "/", reqVersion: "HTTP/1.1",
			status: 200, resVersion: "HTTP/1.1", reason: "OK", reqHeaders: hdrs,
		})
	}
	return press(m, tea.KeyEnter) // open on the newest row, table focus
}

// detailDividerLine returns the rendered Detail divider line from a View dump.
func detailDividerLine(out string) string {
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, "Detail") {
			return ln
		}
	}
	return ""
}

// Tab toggles focus between the table and the open panel; entering panel focus
// pauses follow. Tab is a no-op when the panel is closed.
func TestTabSwitchesFocus(t *testing.T) {
	m := withScrollablePanel()
	if m.panelFocus {
		t.Fatal("panel should not start focused")
	}
	m = press(m, tea.KeyTab)
	if !m.panelFocus {
		t.Error("Tab should move focus into the panel")
	}
	if m.follow {
		t.Error("entering panel focus should pause follow")
	}
	m = press(m, tea.KeyTab)
	if m.panelFocus {
		t.Error("Tab again should return focus to the table")
	}

	closed := press(withRows(5), tea.KeyTab)
	if closed.panelFocus || closed.detailOpen {
		t.Error("Tab with the panel closed should be a no-op")
	}
}

// With the panel focused, ↑↓/jk scroll the body and leave the table selection
// frozen; the offset clamps at the top.
func TestPanelFocusScrollsBodyNotSelection(t *testing.T) {
	m := press(withScrollablePanel(), tea.KeyTab) // panel focus
	sel := m.selected
	m = key(m, "j")
	if m.detailOffset != 1 {
		t.Errorf("j should scroll the body, offset=%d want 1", m.detailOffset)
	}
	if m.selected != sel {
		t.Errorf("selection should stay frozen while scrolling, selected=%d want %d", m.selected, sel)
	}
	m = key(m, "k")
	if m.detailOffset != 0 {
		t.Errorf("k should scroll back up, offset=%d want 0", m.detailOffset)
	}
	m = key(m, "k") // already at the top
	if m.detailOffset != 0 {
		t.Errorf("offset should clamp at 0, got %d", m.detailOffset)
	}
}

// In panel focus, g/G jump to the top/bottom of the body; G lands on the last
// scroll position and never overshoots.
func TestPanelFocusJumpKeys(t *testing.T) {
	m := press(withScrollablePanel(), tea.KeyTab)
	m = key(m, "G")
	if m.detailOffset == 0 {
		t.Fatal("content should overflow, so G must produce a non-zero offset")
	}
	if m.detailOffset != m.maxDetailOffset() {
		t.Errorf("G offset=%d, want maxDetailOffset()=%d", m.detailOffset, m.maxDetailOffset())
	}
	m = key(m, "G") // already at the bottom, must not overshoot
	if m.detailOffset != m.maxDetailOffset() {
		t.Errorf("G at bottom offset=%d, want it pinned to %d", m.detailOffset, m.maxDetailOffset())
	}
	m = key(m, "g")
	if m.detailOffset != 0 {
		t.Errorf("g should jump to the top, offset=%d want 0", m.detailOffset)
	}
}

// Esc steps out one level: panel focus → table focus (panel stays open) → closed.
func TestEscStepsOutOneLevel(t *testing.T) {
	m := press(withScrollablePanel(), tea.KeyTab) // panel focus
	m = press(m, tea.KeyEsc)
	if !m.detailOpen {
		t.Error("first Esc should keep the panel open")
	}
	if m.panelFocus {
		t.Error("first Esc should return focus to the table")
	}
	m = press(m, tea.KeyEsc)
	if m.detailOpen {
		t.Error("second Esc should close the panel")
	}
}

// Moving the table selection resets the panel scroll offset, since the panel is
// now showing a different exchange.
func TestMovingSelectionResetsPanelScroll(t *testing.T) {
	m := press(withScrollablePanel(), tea.KeyTab) // panel focus
	m = key(m, "G")
	if m.detailOffset == 0 {
		t.Fatal("expected a non-zero offset after G")
	}
	m = press(m, tea.KeyTab) // back to the table
	m = key(m, "k")          // move the selection
	if m.detailOffset != 0 {
		t.Errorf("moving the selection should reset panel scroll, offset=%d want 0", m.detailOffset)
	}
}

// The panel shows a ↓ hint when content is hidden below and a ↑ hint when hidden
// above; at the very bottom the ↓ hint is gone.
func TestScrollIndicators(t *testing.T) {
	m := press(withScrollablePanel(), tea.KeyTab)
	top := strings.Join(m.detailBody(), "\n")
	if strings.Contains(top, "↑") {
		t.Errorf("no up indicator at the top:\n%s", top)
	}
	if !strings.Contains(top, "↓") {
		t.Errorf("want a down indicator when content overflows below:\n%s", top)
	}
	m = key(m, "G")
	bottom := strings.Join(m.detailBody(), "\n")
	if !strings.Contains(bottom, "↑") {
		t.Errorf("want an up indicator at the bottom:\n%s", bottom)
	}
	if strings.Contains(bottom, "↓") {
		t.Errorf("no down indicator at the bottom:\n%s", bottom)
	}
}

// The Detail divider carries the ▸ focus marker only when the panel is focused;
// in table focus it leads with a blank gutter.
func TestPanelFocusMarkerOnDivider(t *testing.T) {
	m := withScrollablePanel()
	tableDiv := detailDividerLine(m.View())
	if strings.HasPrefix(tableDiv, markerSelected) {
		t.Errorf("table focus: divider should not carry ▸: %q", tableDiv)
	}
	if !strings.HasPrefix(tableDiv, markerBlank+"─") {
		t.Errorf("table focus: divider should lead with a blank gutter: %q", tableDiv)
	}
	m = press(m, tea.KeyTab)
	panelDiv := detailDividerLine(m.View())
	if !strings.HasPrefix(panelDiv, markerSelected) {
		t.Errorf("panel focus: divider should lead with ▸: %q", panelDiv)
	}
}

// The footer advertises the right keys for each of the three states.
func TestFooterStates(t *testing.T) {
	closed := withRows(5)
	if got := closed.footer(); !strings.Contains(got, "Enter: detail") {
		t.Errorf("closed footer = %q", got)
	}
	open := withScrollablePanel() // already open, table focus
	if got := open.footer(); !strings.Contains(got, "Tab: inspect") {
		t.Errorf("open/table footer = %q", got)
	}
	focused := press(withScrollablePanel(), tea.KeyTab)
	if got := focused.footer(); !strings.Contains(got, "Tab: table") || !strings.Contains(got, "scroll") {
		t.Errorf("open/panel footer = %q", got)
	}
}

// The reverse-video focus bar moves with focus: the selected row wears it while
// the table is focused, and yields it (keeping only its ▸) once focus is in the
// panel. ANSI profile forced so the styling is observable.
func TestRowLineFocusHighlight(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.ANSI)
	t.Cleanup(func() { lipgloss.SetColorProfile(prev) })

	pathWidth := 120 - markerCol - fixedWidth - separators
	r := row{path: "/"}
	if got := rowLine(r, pathWidth, true, true); !strings.Contains(got, "\x1b[") {
		t.Errorf("selected + focused row should be reverse-styled, got %q", got)
	}
	unfocused := rowLine(r, pathWidth, true, false)
	if strings.Contains(unfocused, "\x1b[") {
		t.Errorf("selected but unfocused row should not be styled, got %q", unfocused)
	}
	if !strings.Contains(unfocused, markerSelected) {
		t.Error("an unfocused selected row should keep its ▸ marker")
	}
}

// The Detail divider gets the reverse-video bar only when the panel holds focus,
// so the bright highlight reads as the focus indicator. ANSI profile forced.
func TestDetailDividerFocusStyling(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.ANSI)
	t.Cleanup(func() { lipgloss.SetColorProfile(prev) })

	m := withScrollablePanel() // open, table focus
	if div := detailDividerLine(m.View()); strings.Contains(div, "\x1b[") {
		t.Errorf("table focus: Detail divider should be unstyled, got %q", div)
	}
	m = press(m, tea.KeyTab) // panel focus
	if div := detailDividerLine(m.View()); !strings.Contains(div, "\x1b[") {
		t.Errorf("panel focus: Detail divider should be reverse-styled, got %q", div)
	}
}

// A one-line scroll advances the body by exactly one content line: the up hint
// gets its own reserved line rather than overwriting (and skipping) content.
func TestPanelScrollDoesNotSkipLines(t *testing.T) {
	m := press(withScrollablePanel(), tea.KeyTab) // panel focus
	if body := m.detailBody(); !strings.Contains(body[0], "Request:") {
		t.Fatalf("top line should be the Request label, got %q", body[0])
	}
	m = key(m, "j") // scroll down one
	body := m.detailBody()
	if !strings.Contains(body[0], "↑ 1 more") {
		t.Errorf("after one j, line 0 should be the up hint, got %q", body[0])
	}
	// content[1] is the request start line; seeing it on the next line proves no
	// content was skipped behind the indicator.
	if !strings.Contains(body[1], "GET / HTTP/1.1") {
		t.Errorf("after one j, line 1 should be content[1] (nothing skipped), got %q", body[1])
	}
}

// G scrolls all the way to the final content line — the bottom is fully
// reachable, with no lingering down indicator.
func TestPanelScrollReachesLastLine(t *testing.T) {
	m := key(press(withScrollablePanel(), tea.KeyTab), "G")
	content := detailContent(m.rows[m.selected], m.hexMode)
	last := content[len(content)-1]
	body := strings.Join(m.detailBody(), "\n")
	if !strings.Contains(body, last) {
		t.Errorf("G should reveal the final content line %q:\n%s", last, body)
	}
	if strings.Contains(body, "↓") {
		t.Errorf("no down indicator once the bottom is reached:\n%s", body)
	}
}

// WindowSizeMsg updates the model dimensions and reconciles the scroll anchor
// so the selected row stays visible after a resize. The interesting case is a
// shrink: the selection is parked near the bottom with follow disabled, so
// reducing the height forces top to advance.
func TestWindowSizeMsgUpdatesLayout(t *testing.T) {
	const startH = 40
	m := newModel(120, startH)
	for i := 0; i < 30; i++ {
		next, _ := m.Update(rowMsg(row{path: "/"}))
		m = next.(model)
	}
	// Park the selection one row above the tail with follow off, so it sits
	// well inside the current visible window but close enough to the bottom
	// that a shrink must push top forward to keep it visible.
	m = key(m, "G")
	m = key(m, "k")
	parked := m.selected
	if m.follow {
		t.Fatal("expected follow to be off after moving up")
	}

	// Shrink to a height where top must move for selected to stay visible.
	const newH = 10
	next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: newH})
	m = next.(model)

	if m.width != 120 || m.height != newH {
		t.Errorf("after resize: width=%d height=%d, want 120/%d", m.width, m.height, newH)
	}
	// The selection must be unchanged.
	if m.selected != parked {
		t.Errorf("selected changed from %d to %d after resize", parked, m.selected)
	}
	// The selected row must be inside the new visible window.
	visible := m.visibleRows()
	if m.selected < m.top || m.selected >= m.top+visible {
		t.Errorf("selected row %d outside visible window [%d, %d) after shrink", m.selected, m.top, m.top+visible)
	}
	// top must have advanced to make room.
	if m.top == 0 {
		t.Error("top should have advanced after the shrink, not stayed at 0")
	}
	// View must fit the new height exactly.
	if got := len(strings.Split(m.View(), "\n")); got != newH {
		t.Errorf("View() emitted %d lines after resize to height %d, want %d", got, newH, newH)
	}
}

// Once the ring buffer reaches maxRows the oldest row is dropped on every new
// arrival: the buffer length stays at maxRows, the oldest row is gone, and
// when inspecting (follow off) the selected index shifts down by one to track
// the same logical row.
func TestRingBufferDropsOldestAtCapacity(t *testing.T) {
	m := newModel(120, 24)
	for i := 0; i < maxRows; i++ {
		m = appendRow(m, row{path: fmt.Sprintf("/%d", i)})
	}
	if len(m.rows) != maxRows {
		t.Fatalf("rows = %d, want %d", len(m.rows), maxRows)
	}
	// Park the selection on row 5 (not following) so we can watch it shift.
	m = key(m, "g")
	for i := 0; i < 5; i++ {
		m = key(m, "j")
	}
	if m.selected != 5 {
		t.Fatalf("selected = %d, want 5", m.selected)
	}
	wantPath := m.rows[5].path // remember the logical row we are on

	// One more row pushes the oldest off the front.
	m = appendRow(m, row{path: "/new"})
	if len(m.rows) != maxRows {
		t.Errorf("rows = %d after overflow, want %d", len(m.rows), maxRows)
	}
	// The oldest row (path "/0") is gone; "/1" is now the new head.
	if m.rows[0].path != "/1" {
		t.Errorf("rows[0].path = %q after drop, want /1", m.rows[0].path)
	}
	// The selection shifted down by one to stay on the same logical row.
	if m.selected != 4 {
		t.Errorf("selected = %d after drop, want 4", m.selected)
	}
	if m.rows[m.selected].path != wantPath {
		t.Errorf("rows[selected].path = %q, want %q", m.rows[m.selected].path, wantPath)
	}
	// The newest appended row is at the tail.
	if m.rows[maxRows-1].path != "/new" {
		t.Errorf("tail path = %q, want /new", m.rows[maxRows-1].path)
	}
}

// fitLeft with n=1 keeps the single leading rune without appending an ellipsis.
func TestFitLeftWidthOne(t *testing.T) {
	if got, want := fitLeft("ab", 1), "a"; got != want {
		t.Errorf("fitLeft(%q, 1) = %q, want %q", "ab", got, want)
	}
}

// fitRight with n=1 keeps the single trailing rune without a leading ellipsis.
func TestFitRightWidthOne(t *testing.T) {
	if got, want := fitRight("ab", 1), "b"; got != want {
		t.Errorf("fitRight(%q, 1) = %q, want %q", "ab", got, want)
	}
}

// Init is the Bubble Tea initialiser; it always returns nil.
func TestInitReturnsNil(t *testing.T) {
	if cmd := newModel(120, 24).Init(); cmd != nil {
		t.Errorf("Init() = %v, want nil", cmd)
	}
}

// Pressing q returns a non-nil tea.Quit command.
func TestQuitKeyReturnsCmd(t *testing.T) {
	_, cmd := newModel(120, 24).Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	if cmd == nil {
		t.Error("q should return a non-nil quit cmd")
	}
}

// newRow maps every PairedEvent field to the corresponding row field.
func TestNewRowMapsFields(t *testing.T) {
	pe := http.PairedEvent{
		Pid:    1234,
		Comm:   "curl",
		Method: "GET",
		Path:   "/api",
		Status: 200,
	}
	r := newRow(pe, time.Time{})
	if r.pid != 1234 || r.comm != "curl" || r.method != "GET" || r.path != "/api" || r.status != 200 {
		t.Errorf("newRow mapped fields incorrectly: %+v", r)
	}
}

// detailLineCount returns 0 when there are no rows, even with the panel open.
func TestDetailLineCountEmptyRows(t *testing.T) {
	m := newModel(120, 24)
	m.detailOpen = true
	if got := m.detailLineCount(); got != 0 {
		t.Errorf("detailLineCount with no rows = %d, want 0", got)
	}
}

// clampDetailOffset clamps a detailOffset that overshoots maxDetailOffset.
func TestClampDetailOffsetClampsToMax(t *testing.T) {
	m := withScrollablePanel()
	m.detailOffset = 99999
	m.clampDetailOffset()
	if want := m.maxDetailOffset(); m.detailOffset != want {
		t.Errorf("clampDetailOffset: offset=%d, want max=%d", m.detailOffset, want)
	}
}

// visibleRows clamps to 0 when the terminal height leaves no room for rows.
func TestVisibleRowsZeroOnTinyTerminal(t *testing.T) {
	// height < chromeLines forces v < 0 inside visibleRows, clamped to 0.
	if got := newModel(120, chromeLines-1).visibleRows(); got != 0 {
		t.Errorf("visibleRows on height=%d = %d, want 0", chromeLines-1, got)
	}
}

// bodyLines returns 0 when the terminal is too short to host the panel body.
func TestBodyLinesZeroOnTinyTerminal(t *testing.T) {
	m := newModel(120, chromeLines)
	m.detailOpen = true
	if got := m.bodyLines(); got != 0 {
		t.Errorf("bodyLines on height=%d with open panel = %d, want 0", chromeLines, got)
	}
}

// clampScroll sets top=0 when visibleRows() is zero.
func TestClampScrollZeroVisible(t *testing.T) {
	m := newModel(120, chromeLines)
	m.top = 5
	m.clampScroll()
	if m.top != 0 {
		t.Errorf("clampScroll with visibleRows=0: top=%d, want 0", m.top)
	}
}

// clampScroll clamps top to 0 when it goes negative (defensive guard).
func TestClampScrollTopNegative(t *testing.T) {
	// Directly corrupt top to a negative value; clampScroll must sanitise it.
	m := newModel(120, 10) // visible = 10 - 5 = 5
	m.top = -5
	m.clampScroll()
	if m.top != 0 {
		t.Errorf("clampScroll with top=-5: top=%d, want 0", m.top)
	}
}

// View returns an empty string when either dimension is zero or negative.
func TestViewEmptyOnZeroDimensions(t *testing.T) {
	if got := newModel(0, 24).View(); got != "" {
		t.Errorf("View(width=0) = %q, want empty string", got)
	}
	if got := newModel(120, 0).View(); got != "" {
		t.Errorf("View(height=0) = %q, want empty string", got)
	}
}

// View clamps pathWidth to 1 when the terminal is narrower than the fixed columns.
func TestViewPathWidthClampedToOne(t *testing.T) {
	m := newModel(1, 24)
	for i := 0; i < 3; i++ {
		m = appendRow(m, row{path: "/api/v1"})
	}
	if out := m.View(); out == "" {
		t.Error("View with width=1 should produce output, not an empty string")
	}
}

// detailDivider truncates to m.width when the pid/comm label would overflow.
func TestDetailDividerTruncatesLongLabel(t *testing.T) {
	m := newModel(15, 24)
	m = appendRow(m, row{pid: 99999, comm: "very-long-comm"})
	m.detailOpen = true
	div := m.detailDivider()
	if w := utf8.RuneCountInString(div); w != 15 {
		t.Errorf("detailDivider width = %d, want 15 (model width)", w)
	}
}

// detailBody returns blank placeholder lines when the panel is open but rows is empty.
func TestDetailBodyEmptyRows(t *testing.T) {
	m := newModel(120, 24)
	m.detailOpen = true
	lines := m.detailBody()
	if len(lines) == 0 {
		t.Fatal("detailBody with no rows should return placeholder lines")
	}
	for _, ln := range lines {
		if strings.TrimSpace(ln) != "" {
			t.Errorf("detailBody with no rows: want blank lines, got %q", ln)
		}
	}
}

// detailBody clamps a positive out-of-range offset to maxDetailOffset internally.
func TestDetailBodyOffsetClampedAboveMax(t *testing.T) {
	m := withScrollablePanel()
	m.detailOffset = 99999
	body := strings.Join(m.detailBody(), "\n")
	if strings.Contains(body, "↓") {
		t.Errorf("at clamped max offset there should be no ↓ hint:\n%s", body)
	}
}

// detailBody clamps a negative offset to 0 internally.
func TestDetailBodyOffsetClampedBelowZero(t *testing.T) {
	m := withScrollablePanel()
	m.detailOffset = -5
	body := strings.Join(m.detailBody(), "\n")
	if strings.Contains(body, "↑") {
		t.Errorf("at clamped zero offset there should be no ↑ hint:\n%s", body)
	}
}
