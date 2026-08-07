package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestDiagBuffer_WriteTrimsNewlineAndNotifies(t *testing.T) {
	var notified []string
	d := newDiagBuffer(func(line string) { notified = append(notified, line) })

	n, err := d.Write([]byte("tls: attach failed for pid 123\n"))
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if n != len("tls: attach failed for pid 123\n") {
		t.Errorf("Write returned n = %d, want the full input length", n)
	}
	if len(d.lines) != 1 || d.lines[0] != "tls: attach failed for pid 123" {
		t.Fatalf("lines = %v, want the one line with its newline trimmed", d.lines)
	}
	if len(notified) != 1 || notified[0] != "tls: attach failed for pid 123" {
		t.Errorf("notify callback got %v, want the same trimmed line", notified)
	}
}

func TestDiagBuffer_WriteWithNilNotify(t *testing.T) {
	d := newDiagBuffer(nil)
	if _, err := d.Write([]byte("hello\n")); err != nil {
		t.Fatalf("Write with nil notify returned error: %v", err)
	}
}

func TestDiagBuffer_BoundedAtCap(t *testing.T) {
	d := newDiagBuffer(nil)
	for i := 0; i < diagBufferCap+10; i++ {
		_, _ = fmt.Fprintf(d, "line %d\n", i)
	}
	if len(d.lines) != diagBufferCap {
		t.Fatalf("lines len = %d, want bound at %d", len(d.lines), diagBufferCap)
	}
	if d.lines[0] != "line 10" {
		t.Errorf("oldest retained line = %q, want the FIFO drop to have kept line 10", d.lines[0])
	}
	if last := d.lines[diagBufferCap-1]; last != fmt.Sprintf("line %d", diagBufferCap+9) {
		t.Errorf("newest line = %q, want the most recent write", last)
	}
}

func TestDiagBuffer_Flush(t *testing.T) {
	d := newDiagBuffer(nil)
	_, _ = fmt.Fprintln(d, "first")
	_, _ = fmt.Fprintln(d, "second")

	var buf bytes.Buffer
	d.Flush(&buf)

	want := "first\nsecond\n"
	if got := buf.String(); got != want {
		t.Errorf("Flush wrote %q, want %q", got, want)
	}
}

func TestDiagBuffer_FlushEmpty(t *testing.T) {
	d := newDiagBuffer(nil)
	var buf bytes.Buffer
	d.Flush(&buf)
	if buf.Len() != 0 {
		t.Errorf("Flush of an empty buffer wrote %q, want nothing", buf.String())
	}
}

func TestDiagBuffer_FlushIsIndependentOfLaterWrites(t *testing.T) {
	d := newDiagBuffer(nil)
	_, _ = fmt.Fprintln(d, "first")

	var buf bytes.Buffer
	d.Flush(&buf)
	_, _ = fmt.Fprintln(d, "second") // written after Flush snapshot the slice

	if strings.Contains(buf.String(), "second") {
		t.Errorf("Flush output %q should not include writes after Flush was called", buf.String())
	}
}
