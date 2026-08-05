#!/usr/bin/env bash
# demo-split.sh — prepare the tmux split for 0a-live.tape, run INSIDE the Lima VM.
#   LEFT pane  (demo:0.0): a clean terminal — we run the app here, on camera.
#   RIGHT pane (demo:0.1): tinytap's TUI, pre-filtered to /myapp on an empty table.
# Writes "ready" to /tmp/setup.txt when done; then run `vhs 0a-live.tape` on the Mac.
#
# Things learned the hard way (see also app.py):
#   - The TUI filter matches /proc/pid/comm (TASK_COMM, 15 chars, no args). So we
#     run the app as a python copy named `myapp` -> comm "myapp" -> /myapp isolates
#     it from the server (comm "python"). Hence the `cp` below.
#   - TUI mode discards tinytap's "uprobes attached for pid N" log (io.Discard in
#     run.go), so we can't wait on that log. Instead the probe loop hits the server
#     until a row appears = tinytap is actually capturing (BPF loaded + attached).
#   - `tmux set status off` hides the green status bar so it reads as plain terminals.

set -euo pipefail

cd ~/tinytap-demo || exit 1

# clean slate — these exit non-zero when nothing matches, so `|| true` keeps
# `set -e` from aborting the run
sudo pkill -9 -f "tinytap-demo/tinytap" 2>/dev/null || true
pkill -9 -f server_b.py 2>/dev/null || true
pkill -9 -f "app.py" 2>/dev/null || true
pkill -9 -x myapp 2>/dev/null || true
tmux kill-session -t demo 2>/dev/null || true
sleep 1

# `myapp` = a copy of the venv python (distinct comm for the /myapp filter)
cp -f .venv/bin/python .venv/bin/myapp
# self-signed cert for the local HTTPS server (the client uses verify=False, so
# any self-signed cert works). Generated here if absent — no key is committed.
[ -f server.crt ] || openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout server.key -out server.crt -subj "/CN=localhost" >/dev/null 2>&1
# self-signed HTTPS server that mimics the OpenAI endpoint
setsid .venv/bin/python server_b.py >server.log 2>&1 </dev/null &
sleep 1

# split: left = clean shell, right = tinytap TUI
tmux new-session -d -s demo -x 154 -y 40
tmux set -t demo status off
# bare "$ " prompt (never leak the real username/hostname into a public gif/PR)
# and put .venv/bin on PATH so the app runs as the short `myapp app.py`, which
# keeps the left pane narrow (comm stays "myapp" for the /myapp filter)
tmux send-keys -t demo:0.0 "export PS1='\$ '; export PATH=~/tinytap-demo/.venv/bin:\$PATH; clear" Enter
tmux split-window -h -l 122 -t demo:0.0
tmux send-keys -t demo:0.1 "cd ~/tinytap-demo && sudo ./tinytap --config tinytap.toml" Enter
sleep 5

# probe until tinytap is actually capturing (a server-side row proves BPF is live)
for i in $(seq 1 15); do
  .venv/bin/python -c "import httpx; httpx.Client(verify=False,timeout=2).post('https://127.0.0.1:8443/v1/chat/completions', headers={'Authorization':'Bearer probe'}, json={'x':1})" >/dev/null 2>&1 || true
  [ "$(tmux capture-pane -t demo:0.1 -p | grep -cE 'POST +/v1')" -ge 1 ] && break || true
  sleep 1
done

# pre-apply the /myapp filter (probe rows are comm "python" -> hidden -> empty table),
# clear the left pane, and focus it so the tape can run the app there on camera
tmux send-keys -t demo:0.1 "/"; sleep 0.3; tmux send-keys -t demo:0.1 "myapp"; sleep 0.3; tmux send-keys -t demo:0.1 Enter
tmux send-keys -t demo:0.0 "clear" Enter
tmux select-pane -t demo:0.0
echo ready > /tmp/setup.txt
