package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/shinagawa-web/tinytap/internal/protocols/http"
)

// maxRows bounds the live ring buffer. Beyond this, the oldest row is
// dropped (FIFO) so a long-running capture can't grow memory without limit.
const maxRows = 10000

// Fixed column widths (see #32). PATH is flexible and takes whatever space
// is left after the fixed columns and their single-space separators.
const (
	colTime    = 12 // "19:35:24.123" — millisecond precision, no date
	colPID     = 7  // pid_max = 4194304 is 7 digits
	colComm    = 15 // TASK_COMM_LEN = 16, minus the trailing null
	colMethod  = 7  // longest standard method is OPTIONS
	colStatus  = 6
	colBytes   = 8
	colLatency = 8 // "999.9ms" (the widest value) is 7; the 8th column is breathing room
)

// fixedWidth is the sum of the seven fixed columns; with the seven separator
// spaces between the eight columns, the remainder is PATH's width.
const fixedWidth = colTime + colPID + colComm + colMethod + colStatus + colBytes + colLatency
const separators = 7 // single spaces between the 8 columns

// markerCol is the one-column left gutter carrying the ▸ selection marker
// (blank on unselected rows). It eats into PATH's flexible width so each line
// still fills exactly m.width and nothing wraps.
const markerCol = 1

// Gutter contents. ▸ is a single left-pointing arrow (not box-drawing),
// matching the borderless pgincident style.
const (
	markerSelected = "▸"
	markerBlank    = " "
)

// chromeLines is the non-row height of the table view: top divider, column
// header, header divider, the bottom line, and the footer help line. The
// bottom line is the closing divider when the detail panel is closed, or the
// detail panel's own header divider when it is open — one line either way, so
// chromeLines holds whether the panel is open or not.
const chromeLines = 5

// detailMaxFraction caps the detail panel's share of the row area when open.
// The panel grows to fit its content (#34) rather than claiming a fixed slice,
// but never past this cap — so the table always keeps at least the remaining
// 1-detailMaxFraction of the rows to scroll and navigate, and visibleRows()
// can never reach 0. Originally a fixed 40% split (#40); content-aware sizing
// replaced it so short header sets don't shrink the table for no reason and
// long ones get as much room as the cap allows before truncating.
const detailMaxFraction = 0.6

// detailBodyPlaceholder fills the body line of the detail panel until the
// decoded/hex body view lands (#35); the structured headers above it are live.
const detailBodyPlaceholder = "   body coming in #35"

// row is a single rendered exchange. Values are kept raw (not pre-padded) so
// View can re-truncate PATH/COMM when the terminal is resized.
type row struct {
	time    string // "15:04:05.000", stamped by the sink's time anchor
	pid     uint32
	comm    string
	method  string
	path    string
	status  int
	bytes   int
	latency time.Duration

	// Detail-panel fields: the full start lines and header sets, surfaced
	// only when the panel is open (#34). Headers keep their on-wire order.
	reqVersion string
	resVersion string
	reason     string
	reqHeaders []http.Header
	resHeaders []http.Header
}

func newRow(pe http.PairedEvent, when time.Time) row {
	return row{
		time:    when.Format("15:04:05.000"),
		pid:     pe.Pid,
		comm:    pe.Comm,
		method:  pe.Method,
		path:    pe.Path,
		status:  pe.Status,
		bytes:   pe.ResBytes,
		latency: pe.Latency,

		reqVersion: pe.ReqVersion,
		resVersion: pe.ResVersion,
		reason:     pe.Reason,
		reqHeaders: pe.ReqHeaders,
		resHeaders: pe.ResHeaders,
	}
}

// rowMsg delivers a new exchange from the capture goroutine into the model
// via Program.Send.
type rowMsg row

type model struct {
	rows         []row
	width        int
	height       int
	selected     int  // index into rows of the ▸ row; 0 when rows is empty
	top          int  // index of the first visible row (the scroll anchor)
	follow       bool // when true, selection tracks the newest row as rows arrive
	detailOpen   bool // when true, the bottom detail panel is shown for the selection
	panelFocus   bool // when true (and detailOpen), keys scroll the panel instead of the table
	detailOffset int  // first visible line of the panel body when its content overflows
}

func newModel(width, height int) model {
	// Start in follow mode so the table tracks the live tail until the user
	// scrolls up to inspect.
	return model{width: width, height: height, follow: true}
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab":
			// Toggle focus between the table and the open detail panel. A no-op
			// when the panel is closed (there is nothing to drill into).
			if m.detailOpen {
				m.panelFocus = !m.panelFocus
				if m.panelFocus {
					// You came to read the current row — stop the tail from
					// moving the selection out from under you.
					m.follow = false
				} else {
					m.rearmFollowAtBottom()
				}
			}
		case "enter":
			// Toggle the detail panel for the current selection. Navigation keys
			// keep working while it is open.
			m.detailOpen = !m.detailOpen
			if !m.detailOpen {
				m.panelFocus = false
				m.detailOffset = 0
			}
		case "esc":
			// Step out one level: panel focus → table focus (panel stays open),
			// table focus → close. A no-op in the table-only state.
			switch {
			case m.detailOpen && m.panelFocus:
				m.panelFocus = false
				m.rearmFollowAtBottom()
			case m.detailOpen:
				m.detailOpen = false
				m.detailOffset = 0
			}
		case "up", "k":
			if m.panelFocus {
				m.detailOffset-- // clamped below
				break
			}
			// Moving off the newest row means the user wants to inspect, so
			// stop letting new rows steal the selection.
			if m.selected > 0 {
				m.selected--
			}
			m.follow = false
			m.detailOffset = 0 // the selection changed, so the panel content did too
		case "down", "j":
			if m.panelFocus {
				m.detailOffset++ // clamped below
				break
			}
			if m.selected < len(m.rows)-1 {
				m.selected++
			}
			// Re-arm follow once the selection is back on the newest row.
			if m.selected == len(m.rows)-1 {
				m.follow = true
			}
			m.detailOffset = 0
		case "g":
			if m.panelFocus {
				m.detailOffset = 0
				break
			}
			m.selected = 0
			m.follow = false
			m.detailOffset = 0
		case "G":
			if m.panelFocus {
				m.detailOffset = m.maxDetailOffset()
				break
			}
			if len(m.rows) > 0 {
				m.selected = len(m.rows) - 1
			}
			m.follow = true
			m.detailOffset = 0
		}
	case rowMsg:
		// Append until full, then shift in place so the backing array stays
		// bounded at maxRows instead of growing on every drop.
		if len(m.rows) < maxRows {
			m.rows = append(m.rows, row(msg))
		} else {
			copy(m.rows, m.rows[1:])
			m.rows[maxRows-1] = row(msg)
			// The drop slid every row down one index. While inspecting, follow
			// the same logical row down; if that row was the one dropped, clamp
			// to the new oldest.
			if !m.follow && m.selected > 0 {
				m.selected--
			}
		}
		if m.follow {
			// Following re-pins the selection to the new tail, so the panel is
			// showing a different exchange — reset its scroll.
			m.selected = len(m.rows) - 1
			m.detailOffset = 0
		}
	}
	// Reconcile the scroll anchor after any selection / row-count / size
	// change so the selected row stays inside the visible window.
	m.clampScroll()
	m.clampDetailOffset()
	return m, nil
}

// rearmFollowAtBottom resumes live tracking when the selection already sits on
// the newest row — used when focus returns to the table, so stepping back out of
// the panel at the tail picks the live stream back up.
func (m *model) rearmFollowAtBottom() {
	if len(m.rows) > 0 && m.selected == len(m.rows)-1 {
		m.follow = true
	}
}

// detailLineCount is the full, unclipped height of the selected row's detail
// content (0 when there are no rows).
func (m model) detailLineCount() int {
	if len(m.rows) == 0 {
		return 0
	}
	return len(detailContent(m.rows[m.selected]))
}

// maxDetailOffset is the furthest the panel can scroll. At the bottom the up
// indicator still occupies one body line, so only the last (bodyLines-1) content
// lines are shown — hence the +1 over a naive height subtraction. 0 when the
// content fits.
func (m model) maxDetailOffset() int {
	L, n := m.detailLineCount(), m.bodyLines()
	if L <= n {
		return 0
	}
	return L - (n - 1)
}

// clampDetailOffset keeps the panel scroll offset within [0, maxDetailOffset]
// after any key / selection / resize change.
func (m *model) clampDetailOffset() {
	if max := m.maxDetailOffset(); m.detailOffset > max {
		m.detailOffset = max
	}
	if m.detailOffset < 0 {
		m.detailOffset = 0
	}
}

// visibleRows is how many table rows fit at the current height, after the
// chrome (top divider, header, header divider, bottom line, footer) and the
// detail panel's body, if open.
func (m model) visibleRows() int {
	v := m.height - chromeLines - m.bodyLines()
	if v < 0 {
		v = 0
	}
	return v
}

// bodyLines is the height of the detail panel's body (the lines below its
// header divider), 0 when the panel is closed. The panel grows to fit the
// selected row's detail content but is capped at detailMaxFraction of the row
// area *and* at avail-1, so the table always keeps at least one row and
// visibleRows() can never reach 0 — even if a runtime resize shrinks the
// terminal below the startup floor (#57). With no rows yet it reserves a
// single blank line.
func (m model) bodyLines() int {
	if !m.detailOpen {
		return 0
	}
	avail := m.height - chromeLines
	if avail <= 0 {
		return 0
	}
	max := int(float64(avail) * detailMaxFraction)
	if max > avail-1 {
		max = avail - 1 // leave at least one table row
	}
	if max < 0 {
		max = 0
	}
	want := 1
	if len(m.rows) > 0 {
		want = len(detailContent(m.rows[m.selected]))
	}
	if want > max {
		want = max
	}
	return want
}

// clampScroll moves the scroll anchor only when the selection has left the
// visible window — scrolling up when it rises above `top`, down when it falls
// below the last visible row — and otherwise leaves `top` put. This is what
// keeps the ▸ row stationary on screen while the user steps through rows,
// rather than pinning it to an edge. `top` is then clamped to a valid range.
func (m *model) clampScroll() {
	visible := m.visibleRows()
	if visible <= 0 {
		m.top = 0
		return
	}
	if m.selected < m.top {
		m.top = m.selected
	} else if m.selected >= m.top+visible {
		m.top = m.selected - visible + 1
	}
	maxTop := len(m.rows) - visible
	if maxTop < 0 {
		maxTop = 0
	}
	if m.top > maxTop {
		m.top = maxTop
	}
	if m.top < 0 {
		m.top = 0
	}
}

func (m model) View() string {
	if m.width <= 0 || m.height <= 0 {
		return ""
	}

	// PATH absorbs the slack left after the marker gutter, the fixed columns,
	// and their separators.
	pathWidth := m.width - markerCol - fixedWidth - separators
	if pathWidth < 1 {
		pathWidth = 1
	}
	divider := strings.Repeat("─", m.width)

	// The scroll anchor (m.top) is maintained in Update; here we just render
	// the window [top, top+visible). Capping at `visible` rows keeps the
	// output within the terminal height so the alt-screen never scrolls and
	// pushes the header off the top.
	visible := m.visibleRows()
	start := m.top
	end := start + visible
	if end > len(m.rows) {
		end = len(m.rows)
	}

	// The reverse-video focus bar sits on the table's selected row unless focus
	// has moved into the detail panel, in which case it moves to the panel's
	// divider (below) so it is always obvious which region the keys drive.
	tableFocused := !(m.detailOpen && m.panelFocus)

	lines := make([]string, 0, m.height)
	lines = append(lines, divider, headerLine(pathWidth), divider)
	for i := start; i < end; i++ {
		lines = append(lines, rowLine(m.rows[i], pathWidth, i == m.selected, tableFocused))
	}
	// Pad the table to its full row budget so the bottom line, detail panel,
	// and footer stay pinned to the bottom even before the buffer fills.
	for i := end - start; i < visible; i++ {
		lines = append(lines, "")
	}

	// The line below the table is the closing divider when the panel is closed,
	// or the panel's own header divider (with the selection's pid/comm) when it
	// is open, followed by the placeholder body.
	if m.detailOpen {
		// When the panel holds focus, paint its divider in reverse video — the
		// same bright bar the selected row wears when the table holds focus — so
		// the focus reads at a glance, not from the small ▸ alone.
		div := m.detailDivider()
		if m.panelFocus {
			div = selectedStyle.Render(div)
		}
		lines = append(lines, div)
		lines = append(lines, m.detailBody()...)
	} else {
		lines = append(lines, divider)
	}

	lines = append(lines, m.footer())
	return strings.Join(lines, "\n")
}

// footer is the help line. It has three states: panel closed, panel open with
// table focus, and panel open with panel focus — each advertising the keys that
// do something in that state.
func (m model) footer() string {
	switch {
	case m.detailOpen && m.panelFocus:
		// Esc steps back to table focus here (it doesn't close until the next
		// Esc from the table), so it reads "back", and quit stays advertised.
		return " ↑↓/jk: scroll │ g/G: top/bottom │ Tab: table │ Esc: back │ q: quit"
	case m.detailOpen:
		return " ↑↓/jk: navigate │ Tab: inspect │ Enter/Esc: close │ q: quit"
	default:
		return " ↑↓/jk: navigate │ Enter: detail │ g/G: top/bottom │ q: quit"
	}
}

// detailDivider renders the detail panel's header line for the selected row:
//
//	 ───── Detail ───── pid=5950 (curl) ─────   ← table focus (leading space)
//	▸───── Detail ───── pid=5950 (curl) ─────   ← panel focus
//
// A one-column gutter mirrors the row ▸ marker: blank when the table holds
// focus, ▸ when the panel does. It is exactly m.width display columns wide,
// padded with box-drawing dashes. With no rows selected it omits the pid/comm
// clause.
func (m model) detailDivider() string {
	marker := markerBlank
	if m.panelFocus {
		marker = markerSelected
	}
	label := marker + "───── Detail ───── "
	if len(m.rows) > 0 {
		r := m.rows[m.selected]
		label += fmt.Sprintf("pid=%d (%s) ", r.pid, r.comm)
	}
	n := utf8.RuneCountInString(label)
	if n >= m.width {
		return string([]rune(label)[:m.width])
	}
	return label + strings.Repeat("─", m.width-n)
}

// detailBody returns exactly bodyLines() lines for the selected row: the
// structured request/response header sections (#34), followed by a body
// placeholder (#35). Every line is fit to m.width so a long header value can't
// wrap and push the panel past its fixed height. When the content is taller
// than the panel it scrolls (#61): the body shows content from m.detailOffset,
// reserving a line for a directional hint at each end that has hidden content —
// `↑ N more` above, `↓ N more` below. The hint sits on its own line rather than
// over a content line, so a one-line scroll moves the body by exactly one line
// and no header is skipped behind an indicator.
func (m model) detailBody() []string {
	n := m.bodyLines()
	if n == 0 {
		return nil
	}
	lines := make([]string, n)
	for i := range lines {
		lines[i] = fitLeft("", m.width)
	}
	if len(m.rows) == 0 {
		return lines
	}
	content := detailContent(m.rows[m.selected])
	offset := m.detailOffset
	if max := m.maxDetailOffset(); offset > max {
		offset = max
	}
	if offset < 0 {
		offset = 0
	}

	// Reserve a body line for each end that hides content; the visible content
	// fills what's left, starting after the top hint (if any).
	showUp := offset > 0
	first, avail := 0, n
	if showUp {
		first, avail = 1, n-1
	}
	showDown := offset+avail < len(content)
	if showDown {
		avail--
	}
	for i := 0; i < avail && offset+i < len(content); i++ {
		lines[first+i] = fitLeft(content[offset+i], m.width)
	}
	if showUp {
		lines[0] = fitLeft(fmt.Sprintf(" ↑ %d more", offset), m.width)
	}
	if showDown {
		lines[n-1] = fitLeft(fmt.Sprintf(" ↓ %d more", len(content)-(offset+avail)), m.width)
	}
	return lines
}

// detailContent builds the full, unbounded set of detail lines for a row: a
// Request section (start line + headers) and a Response section, mirroring the
// on-wire order. detailBody clips this to the panel height.
func detailContent(r row) []string {
	lines := []string{" Request:", fmt.Sprintf("   %s %s %s", r.method, r.path, r.reqVersion)}
	lines = append(lines, headerLines(r.reqHeaders)...)
	lines = append(lines, "", " Response:", fmt.Sprintf("   %s %d %s", r.resVersion, r.status, r.reason))
	lines = append(lines, headerLines(r.resHeaders)...)
	lines = append(lines, "", detailBodyPlaceholder)
	return lines
}

// headerLines renders one header section, one "   Name: Value" line per header
// in wire order (three-space indent, matching the start lines under each
// section label). A section with no headers shows an explicit "(none)" so the
// panel never looks like it failed to capture them.
func headerLines(hs []http.Header) []string {
	if len(hs) == 0 {
		return []string{"   (none)"}
	}
	lines := make([]string, len(hs))
	for i, h := range hs {
		lines[i] = fmt.Sprintf("   %s: %s", h.Name, h.Value)
	}
	return lines
}

func headerLine(pathWidth int) string {
	// Numeric columns (STATUS / BYTES / LATENCY) carry right-aligned values,
	// so their labels are right-aligned too — otherwise a label narrower than
	// its column (e.g. BYTES in an 8-wide field) drifts left of the digits.
	return markerBlank + strings.Join([]string{
		fitLeft("TIME", colTime),
		fitLeft("PID", colPID),
		fitLeft("COMM", colComm),
		fitLeft("METHOD", colMethod),
		fitLeft("PATH", pathWidth),
		fitRight("STATUS", colStatus),
		fitRight("BYTES", colBytes),
		fitRight("LATENCY", colLatency),
	}, " ")
}

// selectedStyle renders the ▸ row in reverse video so the selection reads at a
// glance even where the marker glyph is easy to miss.
var selectedStyle = lipgloss.NewStyle().Reverse(true)

// slowLatencyStyle highlights second-scale latencies. "1.2s" and "1.2ms" differ
// by a single character that the eye skips, so the slow case (≥ 1s) is painted
// bold yellow — the unit ceases to be the only signal that a request was slow.
var slowLatencyStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Bold(true)

// rowLine renders one exchange. `selected` draws the ▸ gutter marker (blank
// otherwise); `focused` additionally paints the row in reverse video — the
// bright focus bar. The two are separate so that when focus is in the detail
// panel the selected row keeps its ▸ but yields the highlight to the panel's
// divider. The returned line is exactly m.width display columns wide before
// styling so the columns stay aligned regardless of selection.
func rowLine(r row, pathWidth int, selected, focused bool) string {
	marker := markerBlank
	if selected {
		marker = markerSelected
	}
	// Color the padded cell (not the bare value) so the zero-width escapes
	// leave the column's display width untouched and the table stays aligned.
	latency := fitRight(latencyStr(r.latency), colLatency)
	if r.latency >= time.Second {
		latency = slowLatencyStyle.Render(latency)
	}
	line := marker + strings.Join([]string{
		fitLeft(r.time, colTime),
		fitLeft(strconv.FormatUint(uint64(r.pid), 10), colPID),
		fitLeft(r.comm, colComm),
		fitLeft(r.method, colMethod),
		fitLeft(r.path, pathWidth),
		fitRight(strconv.Itoa(r.status), colStatus),
		fitRight(strconv.Itoa(r.bytes), colBytes),
		latency,
	}, " ")
	if selected && focused {
		return selectedStyle.Render(line)
	}
	return line
}

// latencyStr keeps the value inside the LATENCY budget: "999.9ms" is the widest
// millisecond form (7 columns), so anything >= 1s switches to seconds rather
// than overflow (and be silently clipped by fitRight). The boundary is exactly
// 1s, matching the slowLatencyStyle highlight in rowLine. The ms form is capped
// at 999.9ms so float rounding just under the boundary (e.g. 999.95ms) can't
// emit "1000.0ms" — a value that would read as second-scale yet stay uncolored.
func latencyStr(d time.Duration) string {
	if d < time.Second {
		ms := float64(d) / float64(time.Millisecond)
		if ms > 999.9 {
			ms = 999.9
		}
		return fmt.Sprintf("%.1fms", ms)
	}
	return fmt.Sprintf("%.1fs", float64(d)/float64(time.Second))
}

// fitLeft left-aligns s in a field of n display columns: pad with spaces, or
// keep the front and mark a dropped tail with a trailing ellipsis. Used for
// text columns — PATH (front-priority) and COMM (tail-truncated) both want
// the front kept.
func fitLeft(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		if n <= 1 {
			return string(r[:n])
		}
		return string(r[:n-1]) + "…"
	}
	return s + strings.Repeat(" ", n-len(r))
}

// fitRight right-aligns s in a field of n columns: pad on the left, or, when
// it overflows, keep the tail behind a leading ellipsis so a clipped number
// reads as clipped rather than as a different, smaller value. Used for the
// numeric columns.
func fitRight(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		if n <= 1 {
			return string(r[len(r)-n:])
		}
		return "…" + string(r[len(r)-(n-1):])
	}
	return strings.Repeat(" ", n-len(r)) + s
}
