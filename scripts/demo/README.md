# tinytap 0A demo — "see your app's own HTTPS in plaintext"

Records the GIF (`out.gif`) for the 0A article: run a normal app that calls an
API over HTTPS, and watch tinytap show the exact request it sent — method,
headers, `Authorization: Bearer`, and the JSON body — in plaintext, with no
proxy and no CA certificate installed.

The recording is a tmux split:

- **left** — a plain terminal where the app is run on camera (`myapp app.py`)
- **right** — tinytap's TUI, showing the one captured request and its detail panel

## Files

| file | what it is |
|---|---|
| `app.py` | the demo app — one OpenAI SDK call over HTTPS to a local server |
| `server_b.py` | a self-signed local HTTPS server that mimics the OpenAI endpoint |
| `demo-split.sh` | sets up the tmux split + tinytap inside the VM (run this first) |
| `0a-live.tape` | the [vhs](https://github.com/charmbracelet/vhs) script that records `out.gif` |
| `tinytap.toml` | tinytap config (`output = "tui"`) |

The recording is written to `out.gif`, then copied over `docs/tui-demo.gif` —
the image shown at the top of the repo README.

## Prerequisites

- A Linux host with eBPF (this demo was recorded in a **Lima VM** named
  `tinytap` — quiet, no host noise). tinytap runs there directly.
- The `tinytap` binary (v0.6.2) in `~/tinytap-demo/`.
- A Python venv at `~/tinytap-demo/.venv` with `openai` and `httpx` installed.
- `tmux` and `openssl` in the VM; `vhs` on the machine that records (the Mac).

The self-signed cert (`server.crt` / `server.key`) is **not committed** —
`demo-split.sh` generates it on first run. To make it by hand:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout server.key -out server.crt -subj "/CN=localhost"
```

## Run

```sh
# in the VM: prepare the split (writes "ready" to /tmp/setup.txt)
bash demo-split.sh

# on the recording host: capture the gif, then update the repo's hero image
vhs 0a-live.tape                    # -> out.gif
cp out.gif ../../docs/tui-demo.gif  # shown at the top of the repo README
```

## Why it's written this way (non-obvious bits)

- **`myapp app.py`, not `python3 app.py`.** `myapp` is a copy of the venv
  python, so tinytap's TUI filter (which matches `/proc/pid/comm`, 16 bytes, no
  args) can isolate the app with `/myapp` — plain `python3` collides with the
  server. Do **not** invoke via a symlink: that breaks venv detection and the
  app dies with `ModuleNotFoundError`, silently capturing nothing.
- **One execution = one row.** tinytap's SSL uprobe only captures `SSL_write`
  calls made *after* it attaches (~200ms after first seeing the pid). `app.py`
  therefore opens a payload-less TLS handshake first: that makes tinytap attach
  but writes no application data (no row), and after a short sleep the single
  real request is the only captured row.
- **TUI mode discards the "uprobes attached" log** (`io.Discard` in tinytap's
  `run.go`), so `demo-split.sh` can't wait on that log. Instead it probes the
  server until a row appears — proof that tinytap is actually capturing.
- Recorded on Lima rather than Docker Desktop because Docker Desktop's own
  control traffic would flood the table; Lima has no such host noise.
- Dummy key only (`sk-demo-...`); a real key or Bearer never appears on screen.
