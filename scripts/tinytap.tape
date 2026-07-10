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

Type "ssh -F ~/.lima/tinytap/ssh.config -t lima-tinytap 'cd ~/tinytap/.claude/worktrees/issue-135-tui-gif-demo && bash scripts/demo-tui.sh'"
Enter

# Let the table fill: demo-tui.sh fires its last request at ~6.3s, plus the
# SSH connect/handshake before the script even starts.
Sleep 9s

# Open the detail panel for the newest (currently selected) row.
Enter
Sleep 1s

# Move focus into the panel so j/k scroll its body instead of the table.
Tab
Sleep 500ms

# Scroll — the panel body overflows the terminal height.
Type "jjjjj"
Sleep 1s

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
