//go:build privileged

package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/shinagawa-web/tinytap/internal/loader"
	"github.com/shinagawa-web/tinytap/internal/loader/bpf"
	"golang.org/x/sys/unix"
)

// Diagnostics for #440, not meant to be merged. Earlier runs showed that
// handle_write sometimes doesn't run at all while handle_writev does. These
// tests narrow down what decides that. They only log.

// diagPipeOps issues diagOps writes and diagOps writevs on the calling thread
// and reports how far each program's run counter moved. A nil program is not
// measured and reports -1.
func diagPipeOps(t *testing.T, writeProg, writevProg *ebpf.Program) (writeRuns, writevRuns int64) {
	t.Helper()
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		t.Errorf("pipe: %v", err)
		return -1, -1
	}
	defer unix.Close(p[0])
	defer unix.Close(p[1])

	buf := make([]byte, diagBufSize)
	writes := func() {
		for range diagOps {
			_, _ = unix.Write(p[1], buf)
		}
	}
	writevs := func() {
		for range diagOps {
			_, _ = unix.Writev(p[1], [][]byte{buf})
		}
	}
	writeRuns, writevRuns = -1, -1
	if writeProg != nil {
		writeRuns, _ = diagMeasure(t, writeProg, writes)
	} else {
		writes()
	}
	if writevProg != nil {
		writevRuns, _ = diagMeasure(t, writevProg, writevs)
	} else {
		writevs()
	}
	return writeRuns, writevRuns
}

// TestDiag440_PerCPU pins one thread to each CPU. Earlier runs showed results
// differing between threads in the same round, and this shows whether the
// thread or the CPU it is on decides that.
func TestDiag440_PerCPU(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root / CAP_BPF")
	}
	stats, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		t.Fatalf("EnableStats: %v", err)
	}
	defer stats.Close()

	workers := make([]*diagWorker, runtime.NumCPU())
	for cpu := range workers {
		w := startDiagWorker(fmt.Sprintf("cpu%d", cpu))
		w.run(func() {
			var set unix.CPUSet
			set.Set(cpu)
			if err := unix.SchedSetaffinity(0, &set); err != nil {
				t.Errorf("pin to cpu %d: %v", cpu, err)
			}
		})
		workers[cpu] = w
		defer w.stop()
	}

	for round := range diagRounds + 2 {
		tt, err := loader.Load(0)
		if err != nil {
			t.Fatalf("round %d: Load: %v", round, err)
		}
		writeProg, err := diagFindProg("handle_write")
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		writevProg, err := diagFindProg("handle_writev")
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		// Twice per CPU, to see whether a result holds on the same CPU.
		for pass := range 2 {
			for cpu, w := range workers {
				w.run(func() {
					wr, wv := diagPipeOps(t, writeProg, writevProg)
					t.Logf("diag440cpu round=%d pass=%d cpu=%d tid=%d write=%d writev=%d",
						round, pass, cpu, w.tid, wr, wv)
				})
			}
		}
		writeProg.Close()
		writevProg.Close()
		if err := tt.Close(); err != nil {
			t.Errorf("round %d: Close: %v", round, err)
		}
	}
}

func diagPrograms(o *bpf.TinytapObjects) map[string]*ebpf.Program {
	return map[string]*ebpf.Program{
		"sys_enter_accept4":    o.HandleAccept4,
		"sys_enter_read":       o.HandleRead,
		"sys_enter_write":      o.HandleWrite,
		"sys_enter_close":      o.HandleClose,
		"sys_enter_recvfrom":   o.HandleRecvfrom,
		"sys_enter_sendto":     o.HandleSendto,
		"sys_enter_recvmsg":    o.HandleRecvmsg,
		"sys_enter_sendmsg":    o.HandleSendmsg,
		"sys_enter_writev":     o.HandleWritev,
		"sys_enter_readv":      o.HandleReadv,
		"sys_enter_sendfile64": o.HandleSendfile,
		"sys_exit_read":        o.HandleExitRead,
		"sys_exit_recvfrom":    o.HandleExitRecvfrom,
		"sys_exit_recvmsg":     o.HandleExitRecvmsg,
		"sys_exit_readv":       o.HandleExitReadv,
		"sys_exit_sendfile64":  o.HandleExitSendfile,
	}
}

// TestDiag440_AttachSubset skips the loader and attaches only some of the
// tracepoints, without the fentry program or a ring buffer reader. It shows
// whether handle_write needs the other attachments to go missing.
func TestDiag440_AttachSubset(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root / CAP_BPF")
	}
	stats, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		t.Fatalf("EnableStats: %v", err)
	}
	defer stats.Close()

	all := make([]string, len(loader.Tracepoints))
	for i, tp := range loader.Tracepoints {
		all[i] = tp.Name
	}
	subsets := [][]string{
		{"sys_enter_write"},
		{"sys_enter_read", "sys_enter_write"},
		{"sys_enter_write", "sys_enter_writev"},
		{"sys_enter_writev", "sys_enter_write"},
		all,
	}

	workers := []*diagWorker{startDiagWorker("w0"), startDiagWorker("w1"), startDiagWorker("w2")}
	defer func() {
		for _, w := range workers {
			w.stop()
		}
	}()

	for si, subset := range subsets {
		label := strings.ReplaceAll(strings.Join(subset, "+"), "sys_enter_", "")
		if len(subset) == len(all) {
			label = "all"
		}
		for round := range diagRounds + 2 {
			spec, err := bpf.LoadTinytap()
			if err != nil {
				t.Fatalf("LoadTinytap: %v", err)
			}
			var objs bpf.TinytapObjects
			if err := spec.LoadAndAssign(&objs, nil); err != nil {
				t.Fatalf("LoadAndAssign: %v", err)
			}
			progs := diagPrograms(&objs)

			var links []link.Link
			attached := make(map[string]bool)
			for _, name := range subset {
				l, err := link.Tracepoint("syscalls", name, progs[name], nil)
				if err != nil {
					t.Logf("diag440subset attach %s: %v", name, err)
					continue
				}
				links = append(links, l)
				attached[name] = true
			}

			var writevProg *ebpf.Program
			if attached["sys_enter_writev"] {
				writevProg = objs.HandleWritev
			}
			for _, w := range workers {
				w.run(func() {
					wr, wv := diagPipeOps(t, objs.HandleWrite, writevProg)
					t.Logf("diag440subset subset=%d(%s) round=%d worker=%s write=%d writev=%d",
						si, label, round, w.name, wr, wv)
				})
			}

			for _, l := range links {
				_ = l.Close()
			}
			_ = objs.Close()
		}
	}
}
