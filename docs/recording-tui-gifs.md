# Recording TUI demo GIFs

How to record a GIF of `tinytap`'s `--output tui` mode (e.g. `docs/tui-demo.gif`).

**Everything runs on the Mac host.** You do *not* install `vhs` inside the Lima
VM. `vhs`/`ttyd`/`ffmpeg`/the headless browser that captures frames all live on
the Mac; only `tinytap` itself (which needs eBPF, hence Linux) runs in the VM.
The tape reaches into the VM over `ssh -t`. This is the hand-off doc: point
someone (or an agent) at it and the whole recording is reproducible.

## Prerequisites (verify once)

| What | Check |
|---|---|
| Mac tooling | `which vhs ttyd ffmpeg limactl` — all four must resolve |
| VM running | `limactl list` shows `tinytap` as `Running` |
| `tinytap` built in the VM | the binary exists at the path the tape `cd`s into (build with `make build` in that VM-side checkout) |
| Passwordless sudo in the VM | `limactl shell tinytap -- sudo -n true` succeeds — otherwise a password prompt appears mid-tape and the recording is ruined |

## Recording an existing tape

```bash
# From the Mac checkout, on the branch that has the tape:
vhs scripts/tinytap.tape          # writes the GIF named in the tape's `Output` line
```

Then **verify the result** — a GIF opens as a single still in most viewers, so
extract frames and look at them:

```bash
GIF=docs/tui-demo.gif
# frame count (sanity: a real recording is hundreds of frames)
ffprobe -v error -count_frames -select_streams v:0 \
  -show_entries stream=nb_read_frames -of default=noprint_wrappers=1 "$GIF"
# pull a specific frame out to inspect it
ffmpeg -y -i "$GIF" -vf "select=eq(n\,200)" -vframes 1 /tmp/frame.png
```

Don't trust "it exited 0" — check that the frames actually show the table, the
detail panel, etc. A tiny GIF (tens of KB) is a red flag that the TUI never
rendered.

## Writing a new tape

Copy `scripts/tinytap.tape` as a starting point — its header and the four rules
below are the load-bearing parts. The matching traffic generator is
`scripts/demo-tui.sh` (starts `python3 -m http.server`, fires varied requests,
then runs `sudo ./tinytap --output tui` in the foreground so the tape can drive
the live TUI).

1. **Connect with `ssh -t`, not `limactl shell … -- cmd`.** The `limactl shell`
   *command* form does **not** allocate a remote TTY, so `tinytap`'s TUI refuses
   to start ("needs an interactive terminal") and every subsequent keystroke
   leaks to the host shell instead. Use Lima's generated ssh config, which `-t`
   makes allocate a PTY and forward the window size:
   ```
   Type "ssh -F ~/.lima/tinytap/ssh.config -t lima-tinytap 'cd <VM-side path> && bash scripts/demo-tui.sh'"
   ```

2. **The terminal must be at least 120×24.** `tinytap`'s TUI hard-refuses
   anything smaller (`Terminal too small … got NxN`). `vhs`'s `Set Width`/`Set
   Height` are in **pixels**; at `Set FontSize 16`, `Width 1200` only yields ~105
   columns — too narrow. Use `Set Width 1500` / `Set Height 760` (~145×38). If you
   change the font size, re-check the column count (see "Probing the size" below).

3. **Hide the launch with `Hide` … `Show`** if you don't want the SSH command
   and startup on camera — the GIF then opens straight on the live table:
   ```
   Hide
   Type "ssh … demo-tui.sh"
   Enter
   Sleep 3s          # SSH connect + TUI up (off camera)
   Show
   Sleep 6s          # on camera: rows stream into the table
   ```

4. **Know the TUI focus model when scripting interaction.** With the detail
   panel open, focus starts on the **table**: `j`/`k` moves the table selection
   and the panel body tracks the highlighted row. `Tab` (`inspect`) moves focus
   **into** the panel so `j`/`k` scrolls the panel body; `b` toggles the hex
   view; `Esc` steps back / closes; `q` quits. The footer line always shows the
   bindings for the currently focused pane.

### Probing the terminal size (when changing font/dimensions)

To confirm the VM-side pty ends up ≥120×24 before committing to a full re-record:

```bash
cat > /tmp/probe.tape <<'EOF'
Output "probe.gif"
Set Shell "bash"
Set FontSize 16
Set Width 1500
Set Height 760
Set Padding 10
Type "ssh -F ~/.lima/tinytap/ssh.config -t lima-tinytap stty size > /tmp/remote_size.txt 2>/dev/null"
Enter
Sleep 3s
EOF
(cd /tmp && vhs probe.tape) && cat /tmp/remote_size.txt   # prints "rows cols"
```

## Troubleshooting

| Symptom in the frames | Cause | Fix |
|---|---|---|
| Command types, prompt returns instantly, later keystrokes appear as literal text (`jjjjjbq`) | no remote TTY | use `ssh -t`, not `limactl shell -- cmd` (rule 1) |
| `Terminal too small … got NxN` flashes, then prompt | canvas < 120×24 | widen `Set Width`/`Set Height` (rule 2) |
| Password prompt appears mid-tape | sudo needs a password in the VM | enable passwordless sudo for `tinytap` |
| Blank/near-empty table | `Show` fired before rows streamed, or `Sleep` too short | lengthen the on-camera `Sleep`, or start the traffic earlier |
