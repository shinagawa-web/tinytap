# 0a-live.tape — vhs recording for the tinytap 0A demo
# ("see your app's own HTTPS in plaintext, no proxy, no cert").
#
# Records a tmux split:
#   LEFT  = a plain terminal where we run the app ON CAMERA.
#   RIGHT = tinytap's TUI, showing the one captured request + its detail panel.
#
# Prerequisites — run demo-split.sh in the Lima VM FIRST (it writes "ready" to
# /tmp/setup.txt). It starts a self-signed HTTPS server, tinytap in the right
# pane already filtered to /myapp on an empty table, and leaves the left pane
# focused at a clean prompt. The Lima VM is used (not Docker Desktop) because
# it has no host noise, so the table only ever shows our own traffic.
#
# Design principle: draw the eye with a little motion, then hold completely
# still so the viewer can read the plaintext. Only two on-camera actions —
# run the command, open the detail — and the 6s payoff is frozen.
#
# Run:
#   (in the VM)  bash demo-split.sh      # wait until /tmp/setup.txt says ready
#   (on the Mac) vhs 0a-live.tape        # -> out.gif

Output "out.gif"
Set Shell "bash"
Set FontSize 10
Set Width 960
Set Height 620
Set Theme "Dracula"
Set Padding 6
Set TypingSpeed 90ms

# off camera: attach to the prepared tmux session in the VM
Hide
Type "ssh -F ~/.lima/tinytap/ssh.config -t lima-tinytap 'tmux attach -t demo'"
Enter
Sleep 4s
Show

# beat 1 — a clean terminal on the left, an empty tinytap on the right
Sleep 1500ms

# beat 2 — type and run the app on camera. It is run as `.venv/bin/myapp`
# (a copy of the venv python) so tinytap's /myapp comm filter isolates it.
Type "myapp app.py"
Sleep 400ms
Enter

# beat 3 — app.py does a payload-less TLS handshake (attaches the uprobe, no
# row), waits past the attach, then makes ONE real request -> exactly one
# plaintext row appears on the right; the app prints "done" and exits.
Sleep 4s

# beat 4 — focus the tinytap pane (tmux: Ctrl-b o) and open the detail panel
Ctrl+b
Sleep 250ms
Type "o"
Sleep 500ms
Enter

# beat 5 — payoff, fully still: Authorization: Bearer + readable JSON body.
# Do NOT press "b" (that would switch the body to a hex dump).
Sleep 6s
Hide
