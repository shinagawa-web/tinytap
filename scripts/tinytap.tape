# vhs tape for tinytap's --output tui, driven by scripts/demo-tui.sh.
#
# eBPF only runs on Linux, so this can't record on the Mac host directly —
# it shells into the Lima VM where tinytap is actually built and run, and
# only uses the Mac side for vhs/ttyd/the headless browser that takes the
# screenshots. It connects with `ssh -t` (via Lima's generated ssh.config)
# rather than `limactl shell … -- cmd`, because the latter does not allocate
# a remote TTY and tinytap's TUI refuses to start without one. Run from the
# Mac checkout (the VM-side worktree at
# ~/tinytap/.claude/worktrees/issue-135-tui-gif-demo must already have
# `tinytap` built — `make build`):
#
#   vhs scripts/tinytap.tape
#
# Regenerates docs/tui-demo.gif.

Output docs/tui-demo.gif

Require limactl

Set Shell "bash"
# tinytap's TUI requires at least 120x24; at FontSize 16 this width/height
# yields ~145x38, which `ssh -t` forwards to the VM-side pty.
Set FontSize 16
Set Width 1500
Set Height 760
Set Theme "Dracula"
Set Padding 10
Set TypingSpeed 40ms

# Launch off-camera: hide the SSH handshake and tinytap startup so the GIF
# opens straight on the live table rather than on a typed command. demo-tui.sh
# fires its first request ~1.5s after tinytap starts.
Hide
Type "ssh -F ~/.lima/tinytap/ssh.config -t lima-tinytap 'cd ~/tinytap/.claude/worktrees/issue-135-tui-gif-demo && bash scripts/demo-tui.sh'"
Enter
Sleep 3s
Show

# On-camera: let the remaining requests stream into the table.
Sleep 6s

# Open the detail panel for the selected (newest) row. Focus stays on the
# table, so the next keystrokes still move the table selection.
Enter
Sleep 1.5s

# Scroll the TABLE with the panel open — the detail panel tracks the selected
# row, so its contents switch as the highlight moves up the list.
Type "k"
Sleep 1.2s
Type "k"
Sleep 1.2s
Type "k"
Sleep 1.5s

# Back down to the newest row (it carries a response body), then move focus
# into the panel so j/k now scrolls the panel body instead of the table.
Type "jjj"
Sleep 1.2s
Tab
Sleep 700ms

# Scroll the panel body — it overflows the panel height.
Type "jjjjj"
Sleep 1.5s

# Toggle the body view between decoded and hex.
Type "b"
Sleep 1.5s

# Step focus back to the table, then close the panel.
Escape
Sleep 500ms
Escape
Sleep 500ms

# Quit the TUI — demo-tui.sh's cleanup trap tears down the server.
Type "q"
Sleep 1s
