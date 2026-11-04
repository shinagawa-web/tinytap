//go:build privileged

package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"testing"
	"time"
	"unsafe"

	"github.com/shinagawa-web/tinytap/internal/events"
	"github.com/shinagawa-web/tinytap/internal/loader"
	"golang.org/x/sys/unix"
)

// Diagnostic for #440, not meant to be merged. It compares how many syscalls
// a thread issued with how many events reached the ring buffer, per thread
// and per syscall. It only logs: a miss must not fail the run, because the
// numbers are the result. The zz_ file name keeps it last in a default-order
// package run, so it also sees the process state the earlier tests left.

const (
	diagRounds  = 6
	diagOps     = 50
	diagBurst   = 3000
	diagBufSize = 8
)

type diagKey struct {
	tid     uint32
	syscall uint32
	fd      int32
}

// diagWorker pins one goroutine to one OS thread, so a tid names a thread for
// the whole run and each worker is guaranteed its own thread.
type diagWorker struct {
	name string
	tid  uint32
	jobs chan func()
	done chan struct{}
}

func startDiagWorker(name string) *diagWorker {
	w := &diagWorker{name: name, jobs: make(chan func()), done: make(chan struct{})}
	ready := make(chan uint32)
	go func() {
		runtime.LockOSThread()
		ready <- uint32(unix.Gettid())
		for job := range w.jobs {
			job()
			w.done <- struct{}{}
		}
	}()
	w.tid = <-ready
	return w
}

func (w *diagWorker) run(f func()) {
	w.jobs <- f
	<-w.done
}

func (w *diagWorker) stop() { close(w.jobs) }

// diagDrain reads until the ring has stayed empty past the deadline. The
// deadline is set up front because Reader.SetDeadline blocks while Read holds
// the reader's lock, so it can't be used to interrupt a pending Read.
func diagDrain(tt *loader.Tinytap, pid uint32, wait time.Duration) <-chan map[diagKey]int {
	out := make(chan map[diagKey]int, 1)
	tt.Reader.SetDeadline(time.Now().Add(wait))
	go func() {
		seen := make(map[diagKey]int)
		for {
			rec, err := tt.Reader.Read()
			if err != nil {
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					fmt.Printf("diag440 reader error: %v\n", err)
				}
				out <- seen
				return
			}
			var e events.Event
			if err := events.Decode(rec.RawSample, &e); err != nil || e.Pid != pid {
				continue
			}
			seen[diagKey{e.Tid, e.Syscall, e.Fd}]++
		}
	}()
	return out
}

type diagRow struct {
	worker  string
	tid     uint32
	syscall string
	id      uint32
	fd      int32
	sent    int
}

// diagExercise issues diagOps of each syscall on the worker's own thread and
// fds, so every event can be attributed exactly.
func diagExercise(t *testing.T, w *diagWorker) []diagRow {
	t.Helper()
	var rows []diagRow
	w.run(func() {
		var p [2]int
		if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
			t.Errorf("pipe: %v", err)
			return
		}
		defer unix.Close(p[0])
		defer unix.Close(p[1])
		sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			t.Errorf("socketpair: %v", err)
			return
		}
		defer unix.Close(sp[0])
		defer unix.Close(sp[1])

		buf := make([]byte, diagBufSize)
		for range diagOps {
			_, _ = unix.Write(p[1], buf)
		}
		for range diagOps {
			_, _ = unix.Writev(p[1], [][]byte{buf})
		}
		for range diagOps {
			_, _, _ = unix.Syscall6(unix.SYS_SENDTO, uintptr(sp[0]),
				uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0, 0)
		}
		for range diagOps {
			_, _ = unix.Read(p[0], buf)
		}
		rows = []diagRow{
			{w.name, w.tid, "write", events.SyscallWrite, int32(p[1]), diagOps},
			{w.name, w.tid, "writev", events.SyscallWritev, int32(p[1]), diagOps},
			{w.name, w.tid, "sendto", events.SyscallSendto, int32(sp[0]), diagOps},
			{w.name, w.tid, "read", events.SyscallRead, int32(p[0]), diagOps},
		}
	})
	return rows
}

// diagBurstWrites mirrors the overflow tests: an unpinned goroutine writing
// to an os.Pipe, so the Go scheduler picks the thread as it does for them.
func diagBurstWrites(t *testing.T) (fd int32) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	rc, err := w.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	if err := rc.Control(func(f uintptr) { fd = int32(f) }); err != nil {
		t.Fatalf("Control: %v", err)
	}
	buf := []byte("x")
	for range diagBurst {
		if _, err := w.Write(buf); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	return fd
}

func TestDiag440_EventCoverage(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root / CAP_BPF")
	}
	pid := uint32(os.Getpid())

	// Threads that exist before the first attach, and stay across every
	// attach/detach cycle below.
	pre := []*diagWorker{startDiagWorker("pre0"), startDiagWorker("pre1")}
	defer func() {
		for _, w := range pre {
			w.stop()
		}
	}()

	for round := range diagRounds {
		tt, err := loader.Load(0)
		if err != nil {
			t.Fatalf("round %d: Load: %v", round, err)
		}

		// A thread created after this round's attach.
		post := startDiagWorker("post")
		seenCh := diagDrain(tt, pid, 2*time.Second)

		var rows []diagRow
		for _, w := range append(append([]*diagWorker{}, pre...), post) {
			rows = append(rows, diagExercise(t, w)...)
		}

		// The test goroutine is unpinned, like the overflow tests' writers.
		burstFd := diagBurstWrites(t)

		seen := <-seenCh
		dropped := tt.DropCounts().Ringbuf

		for _, row := range rows {
			got := seen[diagKey{row.tid, row.id, row.fd}]
			t.Logf("diag440 round=%d worker=%s tid=%d syscall=%s sent=%d seen=%d",
				round, row.worker, row.tid, row.syscall, row.sent, got)
		}

		// Skip worker threads: burstFd can reuse the number of a pipe a worker
		// already closed, and their writes are not part of the burst.
		workerTid := map[uint32]bool{post.tid: true}
		for _, w := range pre {
			workerTid[w.tid] = true
		}
		byTid := make(map[uint32]int)
		for k, n := range seen {
			if k.syscall == events.SyscallWrite && k.fd == burstFd && !workerTid[k.tid] {
				byTid[k.tid] += n
			}
		}
		tids := make([]uint32, 0, len(byTid))
		total := 0
		for tid, n := range byTid {
			tids = append(tids, tid)
			total += n
		}
		sort.Slice(tids, func(i, j int) bool { return tids[i] < tids[j] })
		parts := ""
		for _, tid := range tids {
			parts += fmt.Sprintf(" %d:%d", tid, byTid[tid])
		}
		t.Logf("diag440 round=%d burst sent=%d seen=%d ringbufDrops=%d perTid=%s",
			round, diagBurst, total, dropped, parts)

		post.stop()
		if err := tt.Close(); err != nil {
			t.Errorf("round %d: Close: %v", round, err)
		}
	}
}
