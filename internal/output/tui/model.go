package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/shinagawa-web/tinytap/internal/protocols/http"
)

const maxRows = 10000

const (
	colTime    = 12
	colPID     = 7  // pid_max = 4194304 is 7 digits
	colComm    = 15 // TASK_COMM_LEN = 16, minus the trailing null
	colMethod  = 7
	colStatus  = 6
	colBytes   = 8
	colLatency = 8
)

const fixedWidth = colTime + colPID + colComm + colMethod + colStatus + colBytes + colLatency
const separators = 7

const markerCol = 1

const (
	markerSelected = "▸"
	markerBlank    = " "
)

const chromeLines = 5

const maxDiagLines = 1000

const diagChromeLines = 2

const detailMaxFraction = 0.6

const sessionBodyBudget = 8 * 1024 * 1024

type row struct {
	time    string
	pid     uint32
	comm    string
	method  string
	path    string
	status  int
	bytes   int
	latency time.Duration

	reqVersion       string
	resVersion       string
	reason           string
	reqHeaders       []http.Header
	resHeaders       []http.Header
	reqBytes         int
	reqBody          []byte
	resBody          []byte
	reqBodyTruncated bool
	resBodyTruncated bool

	sslFallback bool
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

		reqVersion:       pe.ReqVersion,
		resVersion:       pe.ResVersion,
		reason:           pe.Reason,
		reqHeaders:       pe.ReqHeaders,
		resHeaders:       pe.ResHeaders,
		reqBytes:         pe.ReqBytes,
		reqBody:          pe.ReqBody,
		resBody:          pe.ResBody,
		reqBodyTruncated: pe.ReqBodyTruncated,
		resBodyTruncated: pe.ResBodyTruncated,
		sslFallback:      pe.SSLFallback,
	}
}

func (r row) bodyBytes() int { return len(r.reqBody) + len(r.resBody) }

type rowMsg row

type diagMsg string

type dropsMsg uint64

type model struct {
	rows         []row
	width        int
	height       int
	selected     int
	top          int
	follow       bool
	detailOpen   bool
	panelFocus   bool
	detailOffset int
	hexMode      bool
	bodyBytes    int
	filterMode   bool
	filterTerm   string
	filtered     []int

	diagLines  []string
	diagOpen   bool
	diagOffset int

	drops uint64
}

func newModel(width, height int) model {
	return model{width: width, height: height, follow: true}
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyPressMsg:
		if m.filterMode {
			switch msg.String() {
			case "ctrl+c":
				return m, tea.Quit
			case "esc":
				m.filterMode = false
				m.filterTerm = ""
				m.rebuildFilter()
			case "enter":
				m.filterMode = false
			case "backspace", "delete":
				if r := []rune(m.filterTerm); len(r) > 0 {
					m.filterTerm = string(r[:len(r)-1])
					m.rebuildFilter()
				}
			default:
				if msg.Text != "" {
					m.filterTerm += msg.Text
					m.rebuildFilter()
				}
			}
		} else if m.diagOpen {
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "esc", "d", "enter":
				m.diagOpen = false
				m.diagOffset = 0
			case "up", "k":
				m.diagOffset--
			case "down", "j":
				m.diagOffset++
			case "g":
				m.diagOffset = 0
			case "G":
				m.diagOffset = m.maxDiagOffset()
			}
		} else {
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "d":
				if m.detailOpen {
					m.detailOpen = false
					m.panelFocus = false
					m.detailOffset = 0
				}
				m.diagOpen = true
				m.diagOffset = m.maxDiagOffset()
			case "tab":
				if m.detailOpen {
					m.panelFocus = !m.panelFocus
					if m.panelFocus {
						m.follow = false
					} else {
						m.rearmFollowAtBottom()
					}
				}
			case "enter":
				m.detailOpen = !m.detailOpen
				if !m.detailOpen {
					m.panelFocus = false
					m.detailOffset = 0
				}
			case "esc":
				switch {
				case m.detailOpen && m.panelFocus:
					m.panelFocus = false
					m.rearmFollowAtBottom()
				case m.detailOpen:
					m.detailOpen = false
					m.detailOffset = 0
				case m.filterTerm != "":
					m.filterTerm = ""
					m.rebuildFilter()
				}
			case "up", "k":
				if m.panelFocus {
					m.detailOffset--
					break
				}
				if m.selected > 0 {
					m.selected--
				}
				m.follow = false
				m.detailOffset = 0
			case "down", "j":
				if m.panelFocus {
					m.detailOffset++
					break
				}
				if m.selected < m.displayCount()-1 {
					m.selected++
				}
				if m.selected == m.displayCount()-1 {
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
				if m.displayCount() > 0 {
					m.selected = m.displayCount() - 1
				}
				m.follow = true
				m.detailOffset = 0
			case "b", "h":
				m.hexMode = !m.hexMode
			case "/":
				m.filterMode = true
			}
		}
	case rowMsg:
		nr := row(msg)
		if len(m.rows) < maxRows {
			m.rows = append(m.rows, nr)
		} else {
			droppedVisible := m.filterTerm == "" || rowMatchesFilter(m.rows[0], strings.ToLower(m.filterTerm))
			m.bodyBytes -= m.rows[0].bodyBytes()
			copy(m.rows, m.rows[1:])
			m.rows[maxRows-1] = nr
			if !m.follow && m.selected > 0 && droppedVisible {
				m.selected--
			}
		}
		m.rebuildFilter()
		m.bodyBytes += nr.bodyBytes()
		m.evictBodiesOverBudget()
		if m.follow {
			if dc := m.displayCount(); dc > 0 {
				m.selected = dc - 1
			}
			m.detailOffset = 0
		}
	case diagMsg:
		line := string(msg)
		if len(m.diagLines) < maxDiagLines {
			m.diagLines = append(m.diagLines, line)
		} else {
			copy(m.diagLines, m.diagLines[1:])
			m.diagLines[maxDiagLines-1] = line
		}
		if m.diagOpen {
			m.diagOffset = m.maxDiagOffset()
		}
	case dropsMsg:
		m.drops = uint64(msg)
	}
	m.clampScroll()
	m.clampDetailOffset()
	m.clampDiagOffset()
	return m, nil
}

func (m *model) rearmFollowAtBottom() {
	if dc := m.displayCount(); dc > 0 && m.selected == dc-1 {
		m.follow = true
	}
}

func (m model) detailLineCount() int {
	if m.displayCount() == 0 {
		return 0
	}
	return len(detailContent(m.displayRow(m.selected), m.hexMode))
}

func (m model) maxDetailOffset() int {
	L, n := m.detailLineCount(), m.bodyLines()
	if L <= n {
		return 0
	}
	return L - (n - 1)
}

func (m *model) clampDetailOffset() {
	if max := m.maxDetailOffset(); m.detailOffset > max {
		m.detailOffset = max
	}
	if m.detailOffset < 0 {
		m.detailOffset = 0
	}
}

func (m model) maxDiagOffset() int {
	n := m.diagContentLines()
	if len(m.diagLines) <= n {
		return 0
	}
	return len(m.diagLines) - n
}

func (m *model) clampDiagOffset() {
	if max := m.maxDiagOffset(); m.diagOffset > max {
		m.diagOffset = max
	}
	if m.diagOffset < 0 {
		m.diagOffset = 0
	}
}

func (m model) diagContentLines() int {
	n := m.height - diagChromeLines
	if n < 0 {
		n = 0
	}
	return n
}

func (m model) visibleRows() int {
	v := m.height - chromeLines - m.bodyLines()
	if v < 0 {
		v = 0
	}
	return v
}

func (m model) bodyLines() int {
	if !m.detailOpen {
		return 0
	}
	avail := m.height - chromeLines
	if avail <= 0 {
		return 0
	}
	max := int(float64(avail) * detailMaxFraction)
	want := 1
	if len(m.rows) > 0 {
		want = m.detailLineCount()
	}
	if want > max {
		want = max
	}
	return want
}

func (m *model) clampScroll() {
	if dc := m.displayCount(); dc > 0 && m.selected >= dc {
		m.selected = dc - 1
	} else if dc == 0 {
		m.selected = 0
	}
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
	maxTop := m.displayCount() - visible
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

func (m model) View() tea.View {
	v := tea.NewView(m.viewContent())
	v.AltScreen = true
	return v
}

func (m model) viewContent() string {
	if m.width <= 0 || m.height <= 0 {
		return ""
	}
	if m.diagOpen {
		return m.diagView()
	}

	pathWidth := m.width - markerCol - fixedWidth - separators
	if pathWidth < 1 {
		pathWidth = 1
	}
	divider := strings.Repeat("─", m.width)

	visible := m.visibleRows()
	start := m.top
	end := start + visible
	if end > m.displayCount() {
		end = m.displayCount()
	}

	tableFocused := !m.detailOpen || !m.panelFocus

	lines := make([]string, 0, m.height)
	lines = append(lines, divider, headerLine(pathWidth), divider)
	for i := start; i < end; i++ {
		lines = append(lines, rowLine(m.displayRow(i), pathWidth, i == m.selected, tableFocused))
	}
	for i := end - start; i < visible; i++ {
		lines = append(lines, "")
	}

	if m.detailOpen {
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

func (m model) diagView() string {
	label := "───── Diagnostics "
	if n := len(m.diagLines); n > 0 {
		label += fmt.Sprintf("(%d) ", n)
	}
	if w := utf8.RuneCountInString(label); w < m.width {
		label += strings.Repeat("─", m.width-w)
	} else if w > m.width {
		label = string([]rune(label)[:m.width])
	}

	n := m.diagContentLines()
	offset := m.diagOffset
	if max := m.maxDiagOffset(); offset > max {
		offset = max
	}
	if offset < 0 {
		offset = 0
	}

	lines := make([]string, 0, m.height)
	lines = append(lines, label)
	shown := 0
	for ; shown < n && offset+shown < len(m.diagLines); shown++ {
		lines = append(lines, fitLeft(" "+m.diagLines[offset+shown], m.width))
	}
	for ; shown < n; shown++ {
		lines = append(lines, fitLeft("", m.width))
	}
	lines = append(lines, " ↑↓/jk: scroll │ g/G: top/bottom │ Esc/d/Enter: close │ q: quit")
	return strings.Join(lines, "\n")
}

func (m model) footer() string {
	if m.filterMode {
		return fmt.Sprintf(" /%s │ Enter: apply │ Esc: clear", m.filterTerm)
	}
	mode := "hex"
	if m.hexMode {
		mode = "text"
	}
	drop := m.dropIndicator()
	diag := m.diagIndicator()
	switch {
	case m.detailOpen && m.panelFocus:
		return fmt.Sprintf(" ↑↓/jk: scroll │ g/G: top/bottom │ Tab: table │ b: %s body │ Esc: back │ q: quit%s%s", mode, drop, diag)
	case m.detailOpen:
		return fmt.Sprintf(" ↑↓/jk: navigate │ Tab: inspect │ b: %s body │ Enter/Esc: close │ q: quit%s%s", mode, drop, diag)
	default:
		if m.filterTerm != "" {
			return fmt.Sprintf(" [/%s] ↑↓/jk: navigate │ Enter: detail │ /: edit │ Esc: clear │ q: quit%s%s", m.filterTerm, drop, diag)
		}
		return fmt.Sprintf(" ↑↓/jk: navigate │ Enter: detail │ g/G: top/bottom │ /: filter │ q: quit%s%s", drop, diag)
	}
}

func (m model) dropIndicator() string {
	if m.drops > 0 {
		return " │ " + dropStyle.Render(fmt.Sprintf("⚠ %d dropped", m.drops))
	}
	return ""
}

func (m model) diagIndicator() string {
	if n := len(m.diagLines); n > 0 {
		return " │ " + slowLatencyStyle.Render(fmt.Sprintf("⚠ %d diag (d)", n))
	}
	return ""
}

// ───── Detail ───── pid=5950 (curl) ─────
func (m model) detailDivider() string {
	marker := markerBlank
	if m.panelFocus {
		marker = markerSelected
	}
	label := marker + "───── Detail ───── "
	if m.displayCount() > 0 {
		r := m.displayRow(m.selected)
		label += fmt.Sprintf("pid=%d (%s) ", r.pid, r.comm)
		if r.sslFallback {
			label += "[ssl-keyed, fd unverified] "
		}
	}
	n := utf8.RuneCountInString(label)
	if n >= m.width {
		return string([]rune(label)[:m.width])
	}
	return label + strings.Repeat("─", m.width-n)
}

func (m model) detailBody() []string {
	n := m.bodyLines()
	if n == 0 {
		return nil
	}
	lines := make([]string, n)
	for i := range lines {
		lines[i] = fitLeft("", m.width)
	}
	if m.displayCount() == 0 {
		return lines
	}
	content := detailContent(m.displayRow(m.selected), m.hexMode)
	offset := m.detailOffset
	if max := m.maxDetailOffset(); offset > max {
		offset = max
	}
	if offset < 0 {
		offset = 0
	}

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

func detailContent(r row, hex bool) []string {
	lines := []string{" Request:", fmt.Sprintf("   %s %s %s", r.method, r.path, r.reqVersion)}
	lines = append(lines, headerLines(r.reqHeaders)...)
	lines = append(lines, bodyBlock("Request body", r.reqBody, r.reqBytes, r.reqBodyTruncated, hex, r.reqHeaders)...)
	lines = append(lines, "", " Response:", fmt.Sprintf("   %s %d %s", r.resVersion, r.status, r.reason))
	lines = append(lines, headerLines(r.resHeaders)...)
	lines = append(lines, bodyBlock("Response body", r.resBody, r.bytes, r.resBodyTruncated, hex, r.resHeaders)...)
	return lines
}

func bodyBlock(label string, body []byte, total int, truncated, hex bool, headers []http.Header) []string {
	if len(body) == 0 {
		return nil
	}
	if ct, ok := binaryContentType(headers); ok {
		line := fmt.Sprintf(" %s: [%s, %d bytes", label, ct, total)
		if truncated {
			line += " — truncated"
		}
		line += "]"
		return []string{"", line}
	}
	mode := "decoded"
	if hex {
		mode = "hex"
	}
	head := fmt.Sprintf(" %s (%s, %d/%d bytes", label, mode, len(body), total)
	if truncated {
		head += " — truncated"
	}
	head += "):"

	out := []string{"", head}
	if hex {
		return append(out, hexLines(body)...)
	}
	return append(out, decodedLines(body)...)
}

var binaryContentTypes = []string{"image/", "video/", "audio/", "font/", "application/octet-stream", "application/pdf"}

func binaryContentType(headers []http.Header) (string, bool) {
	for _, h := range headers {
		if !strings.EqualFold(h.Name, "Content-Type") {
			continue
		}
		ct := strings.TrimSpace(h.Value)
		if i := strings.IndexByte(ct, ';'); i >= 0 {
			ct = strings.TrimSpace(ct[:i])
		}
		lower := strings.ToLower(ct)
		for _, prefix := range binaryContentTypes {
			if strings.HasSuffix(prefix, "/") && strings.HasPrefix(lower, prefix) {
				return ct, true
			}
			if lower == prefix {
				return ct, true
			}
		}
		return ct, false
	}
	return "", false
}

func decodedLines(body []byte) []string {
	var lines []string
	var b strings.Builder
	for _, c := range body {
		switch {
		case c == '\n':
			lines = append(lines, "   "+b.String())
			b.Reset()
		case c == '\r':
		case c >= 0x20 && c <= 0x7e:
			b.WriteByte(c)
		default:
			b.WriteByte('.')
		}
	}
	return append(lines, "   "+b.String())
}

func hexLines(body []byte) []string {
	var lines []string
	for off := 0; off < len(body); off += 16 {
		end := off + 16
		if end > len(body) {
			end = len(body)
		}
		chunk := body[off:end]
		var hexCol, ascii strings.Builder
		for i := 0; i < 16; i++ {
			if i == 8 {
				hexCol.WriteByte(' ')
			}
			if i < len(chunk) {
				fmt.Fprintf(&hexCol, "%02x ", chunk[i])
				if c := chunk[i]; c >= 0x20 && c <= 0x7e {
					ascii.WriteByte(c)
				} else {
					ascii.WriteByte('.')
				}
			} else {
				hexCol.WriteString("   ")
			}
		}
		lines = append(lines, fmt.Sprintf("   %08x: %s|%s|", off, hexCol.String(), ascii.String()))
	}
	return lines
}

func (m *model) evictBodiesOverBudget() {
	for i := 0; i < len(m.rows) && m.bodyBytes > sessionBodyBudget; i++ {
		n := m.rows[i].bodyBytes()
		if n == 0 {
			continue
		}
		m.rows[i].reqBody = nil
		m.rows[i].resBody = nil
		m.bodyBytes -= n
	}
}

func (m model) displayCount() int {
	if m.filtered != nil {
		return len(m.filtered)
	}
	return len(m.rows)
}

func (m model) displayRow(i int) row {
	if m.filtered != nil {
		return m.rows[m.filtered[i]]
	}
	return m.rows[i]
}

func (m *model) rebuildFilter() {
	if m.filterTerm == "" {
		m.filtered = nil
		return
	}
	term := strings.ToLower(m.filterTerm)
	result := make([]int, 0, cap(m.filtered))
	for i, r := range m.rows {
		if rowMatchesFilter(r, term) {
			result = append(result, i)
		}
	}
	m.filtered = result
}

func rowMatchesFilter(r row, lowerTerm string) bool {
	return strings.Contains(strings.ToLower(r.comm), lowerTerm) ||
		strings.Contains(strings.ToLower(r.path), lowerTerm)
}

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

var selectedStyle = lipgloss.NewStyle().Reverse(true)

var slowLatencyStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Bold(true)

var dropStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)

var sslFallbackStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("13"))

func rowLine(r row, pathWidth int, selected, focused bool) string {
	marker := markerBlank
	if selected {
		marker = markerSelected
	}
	latency := fitRight(latencyStr(r.latency), colLatency)
	if r.latency >= time.Second {
		latency = slowLatencyStyle.Render(latency)
	}
	pidCell := fitLeft(strconv.FormatUint(uint64(r.pid), 10), colPID)
	if r.sslFallback {
		pidCell = sslFallbackStyle.Render(pidCell)
	}
	line := marker + strings.Join([]string{
		fitLeft(r.time, colTime),
		pidCell,
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
