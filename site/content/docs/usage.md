---
title: Usage
weight: 3
---

# Usage

[Quick Start]({{< relref "quick-start" >}}) gets `tinytap` running. This page
covers what to do once it's up: reading the TUI, reading the `stdout` line
format, and when to reach for `verbose` or `doctor`.

## TUI

`output = "auto"` (the default) opens the TUI whenever stdout/stdin are an
interactive terminal of at least 120x24. See
[Configuration]({{< relref "configuration" >}}) to force it with `output =
"tui"` or opt out with `output = "stdout"`.

<img src="/tui-demo.gif" width="800" alt="tinytap's TUI: the request table on top, and the detail panel below showing the full request and response, including headers and the decoded JSON body">

### Request table

Every captured exchange is a row: timestamp, `process[pid]`, method, path,
status, response size, latency. New rows arrive at the bottom; the view
follows the newest row automatically until you scroll away from it.

| Key | Does |
|---|---|
| `j` / `↓`, `k` / `↑` | Move the selection (stops following new rows) |
| `g` / `G` | Jump to the oldest / newest row (`G` re-arms following) |
| `/` | Start typing a filter, matches live as you type |
| `Enter` (while filtering) | Keep the filter, stop editing it |
| `Esc` (while filtering) | Clear the filter |
| `Enter` | Open the detail panel for the selected row |
| `d` | Open the diagnostics panel |
| `q` / `Ctrl-C` | Quit |

### Detail panel

`Enter` on a row opens its full request/response: headers, JSON body when
decodable, hex otherwise. From there:

| Key | Does |
|---|---|
| `Tab` | Move focus into the detail panel to scroll long headers/bodies independently of the table |
| `j`/`k`, `g`/`G` | Scroll the detail panel once it has focus |
| `b` | Toggle hex/text body view |
| `Esc` | Step back out: unfocus the panel, then close it |
| `Enter` | Close the detail panel |

### Diagnostics panel

`tinytap` redirects its own internal log lines (process attach/detach,
TLS uprobe attach, teardown errors) into a diagnostics buffer instead of
printing them over the TUI, since a bare `log.Printf` mid-render would
corrupt the screen. Press `d` to view them; the footer shows `⚠ N diag (d)`
whenever there are lines waiting. They're flushed to stderr when `tinytap`
exits, so nothing is lost if you never open the panel. `g`/`G` jump to the
top/bottom; `Esc`, `d`, or `Enter` closes it.

## `stdout` mode

`output = "stdout"` prints one line per exchange instead of drawing the TUI,
useful when piping into `grep`/`jq`, running over SSH, or in CI:

```text
2026-08-01T12:47:57.005+09:00  python3[27122]  GET   /                        200    1304B     0.3ms
2026-08-01T12:47:57.005+09:00  curl[1234]       GET   /api                     ABANDONED     12.3ms  (peer closed)
```

Each line has a timestamp, `process[pid]`, method, and path, then either the
response (`status`, response size, latency) or `ABANDONED` with a reason:
`peer closed` (the connection closed before a response arrived) or
`timeout` (no response showed up before `tinytap` gave up waiting).

`verbose = true` hangs the full request and response, every header, `>` for
outgoing (the request), `<` for incoming (the response), under each line:

```text
    > GET /api HTTP/1.1
    > Host: localhost:8000
    < HTTP/1.1 200 OK
    < Content-Type: application/json
```

## `doctor`

`tinytap doctor` runs a read-only preflight (kernel version, capabilities,
libssl execute bit) without loading any eBPF. Run it first when something
doesn't work; see [Troubleshooting]({{< relref "troubleshooting" >}}).

## `--version`

Prints the build's version, commit, and date, and exits before touching
eBPF at all. Safe to run without root or capabilities.
