package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestPrintVersion(t *testing.T) {
	oldVersion, oldCommit, oldDate := version, commit, date
	version, commit, date = "v1.2.3", "abc1234", "2026-01-01T00:00:00Z"
	defer func() { version, commit, date = oldVersion, oldCommit, oldDate }()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	printVersion()

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}

	got := buf.String()
	for _, want := range []string{"v1.2.3", "abc1234", "2026-01-01T00:00:00Z"} {
		if !strings.Contains(got, want) {
			t.Errorf("printVersion() = %q, want it to contain %q", got, want)
		}
	}
}
