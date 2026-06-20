package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

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
	colLatency = 7
)

// fixedWidth is the sum of the seven fixed columns; with the six separator
// spaces between the eight columns, the remainder is PATH's width.
const fixedWidth = colTime + colPID + colComm + colMethod + colStatus + colBytes + colLatency
const separators = 7 // single spaces between the 8 columns

// markerCol is the one-column left gutter carrying the ▸ selection marker
// (blank on every other row). It eats into PATH's flexible width so each line
// still fills exactly m.width and nothing wraps.
const markerCol = 1

// Gutter contents. ▸ is a single left-pointing arrow (not box-drawing),
// matching the borderless pgincident style.
const (
	markerSelected = "▸"
	markerBlank    = " "
)

// chromeLines is the non-row height of the table view: top divider, column
// header, header divider, bottom divider, and the footer help line.
const chromeLines = 5

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
	}
}

// rowMsg delivers a new exchange from the capture goroutine into the model
// via Program.Send.
type rowMsg row

type model struct {
	rows     []row
	width    int
	height   int
	selected int  // index into rows of the ▸ row; 0 when rows is empty
	top      int  // index of the first visible row (the scroll anchor)
	follow   bool // when true, selection tracks the newest row as rows arrive
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
		case "up", "k":
			// Moving off the newest row means the user wants to inspect, so
			// stop letting new rows steal the selection.
			if m.selected > 0 {
				m.selected--
			}
			m.follow = false
		case "down", "j":
			if m.selected < len(m.rows)-1 {
				m.selected++
			}
			// Re-arm follow once the selection is back on the newest row.
			if m.selected == len(m.rows)-1 {
				m.follow = true
			}
		case "g":
			m.selected = 0
			m.follow = false
		case "G":
			if len(m.rows) > 0 {
				m.selected = len(m.rows) - 1
			}
			m.follow = true
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
			m.selected = len(m.rows) - 1
		}
	}
	// Reconcile the scroll anchor after any selection / row-count / size
	// change so the selected row stays inside the visible window.
	m.clampScroll()
	return m, nil
}

// visibleRows is how many table rows fit above the chrome at the current
// height (top divider, header, header divider, bottom divider, footer).
func (m model) visibleRows() int {
	v := m.height - chromeLines
	if v < 0 {
		v = 0
	}
	return v
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

	lines := make([]string, 0, visible+3)
	lines = append(lines, divider, headerLine(pathWidth), divider)
	for i := start; i < end; i++ {
		lines = append(lines, rowLine(m.rows[i], pathWidth, i == m.selected))
	}
	lines = append(lines, divider)
	table := strings.Join(lines, "\n")

	// Split-pane scaffold: table on top, detail panel below collapsed to
	// zero height (its content lands in #40). Joining only the non-empty
	// sections keeps the collapsed panel from costing a blank line.
	footer := " ↑↓/jk: navigate │ g/G: top/bottom │ q: quit"
	return lipgloss.JoinVertical(lipgloss.Left, table, footer)
}

func headerLine(pathWidth int) string {
	return markerBlank + strings.Join([]string{
		fitLeft("TIME", colTime),
		fitLeft("PID", colPID),
		fitLeft("COMM", colComm),
		fitLeft("METHOD", colMethod),
		fitLeft("PATH", pathWidth),
		fitLeft("STATUS", colStatus),
		fitLeft("BYTES", colBytes),
		fitLeft("LATENCY", colLatency),
	}, " ")
}

// selectedStyle renders the ▸ row in reverse video so the selection reads at a
// glance even where the marker glyph is easy to miss.
var selectedStyle = lipgloss.NewStyle().Reverse(true)

// rowLine renders one exchange. The leading gutter holds ▸ when selected
// (blank otherwise); the selected row is also reverse-styled. The returned
// line is exactly m.width display columns wide before styling so the columns
// stay aligned regardless of selection.
func rowLine(r row, pathWidth int, selected bool) string {
	marker := markerBlank
	if selected {
		marker = markerSelected
	}
	line := marker + strings.Join([]string{
		fitLeft(r.time, colTime),
		fitLeft(strconv.FormatUint(uint64(r.pid), 10), colPID),
		fitLeft(r.comm, colComm),
		fitLeft(r.method, colMethod),
		fitLeft(r.path, pathWidth),
		fitRight(strconv.Itoa(r.status), colStatus),
		fitRight(strconv.Itoa(r.bytes), colBytes),
		fitRight(latencyStr(r.latency), colLatency),
	}, " ")
	if selected {
		return selectedStyle.Render(line)
	}
	return line
}

// latencyStr keeps the value inside the 7-column LATENCY budget: "999.9ms"
// is the widest millisecond form, so 1s and above switch to seconds rather
// than overflow (and be silently clipped by fitRight).
func latencyStr(d time.Duration) string {
	ms := float64(d) / float64(time.Millisecond)
	if ms < 1000 {
		return fmt.Sprintf("%.1fms", ms)
	}
	return fmt.Sprintf("%.1fs", ms/1000)
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
