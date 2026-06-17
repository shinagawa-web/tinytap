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
	rows   []row
	width  int
	height int
}

func newModel(width, height int) model {
	return model{width: width, height: height}
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
		}
	case rowMsg:
		// Append until full, then shift in place so the backing array stays
		// bounded at maxRows instead of growing on every drop.
		if len(m.rows) < maxRows {
			m.rows = append(m.rows, row(msg))
		} else {
			copy(m.rows, m.rows[1:])
			m.rows[maxRows-1] = row(msg)
		}
	}
	return m, nil
}

func (m model) View() string {
	if m.width <= 0 || m.height <= 0 {
		return ""
	}

	pathWidth := m.width - fixedWidth - separators
	if pathWidth < 1 {
		pathWidth = 1
	}
	divider := strings.Repeat("─", m.width)

	// Tail of the ring buffer that fits above the chrome; selection is
	// pinned to the newest row, so we always show the most recent rows.
	visible := m.height - chromeLines
	if visible < 0 {
		visible = 0
	}
	start := len(m.rows) - visible
	if start < 0 {
		start = 0
	}

	lines := make([]string, 0, visible+3)
	lines = append(lines, divider, headerLine(pathWidth), divider)
	for _, r := range m.rows[start:] {
		lines = append(lines, rowLine(r, pathWidth))
	}
	lines = append(lines, divider)
	table := strings.Join(lines, "\n")

	// Split-pane scaffold: table on top, detail panel below collapsed to
	// zero height (its content lands in #40). Joining only the non-empty
	// sections keeps the collapsed panel from costing a blank line.
	footer := " q: quit"
	return lipgloss.JoinVertical(lipgloss.Left, table, footer)
}

func headerLine(pathWidth int) string {
	return strings.Join([]string{
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

func rowLine(r row, pathWidth int) string {
	return strings.Join([]string{
		fitLeft(r.time, colTime),
		fitLeft(strconv.FormatUint(uint64(r.pid), 10), colPID),
		fitLeft(r.comm, colComm),
		fitLeft(r.method, colMethod),
		fitLeft(r.path, pathWidth),
		fitRight(strconv.Itoa(r.status), colStatus),
		fitRight(strconv.Itoa(r.bytes), colBytes),
		fitRight(latencyStr(r.latency), colLatency),
	}, " ")
}

func latencyStr(d time.Duration) string {
	return fmt.Sprintf("%.1fms", float64(d)/float64(time.Millisecond))
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

// fitRight right-aligns s in a field of n columns: pad on the left, or keep
// the tail if it overflows. Used for the numeric columns.
func fitRight(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[len(r)-n:])
	}
	return strings.Repeat(" ", n-len(r)) + s
}
