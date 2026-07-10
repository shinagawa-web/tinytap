# vhs tape for tinytap's --output tui, driven by scripts/demo-tui.sh.
#
# eBPF only runs on Linux, so this can't record on the Mac host directly —
# it shells into the Lima VM (`limactl shell`) where tinytap is actually
# built and run, and only uses the Mac side for vhs/ttyd/the headless
# browser that takes the screenshots. Run from the Mac checkout (the VM-side
# worktree at ~/tinytap/.claude/worktrees/issue-135-tui-gif-demo must already
# have `tinytap` built — `make build`):
#
#   vhs scripts/tinytap.tape
#
# Regenerates docs/tui-demo.gif.

Output docs/tui-demo.gif

Require limactl

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 720
Set Theme "Dracula"
Set Padding 10
Set TypingSpeed 40ms

Type "limactl shell tinytap -- bash -c 'cd ~/tinytap/.claude/worktrees/issue-135-tui-gif-demo && bash scripts/demo-tui.sh'"
Enter

# Let the table fill: demo-tui.sh fires its last request at ~6.3s.
Sleep 7s

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
