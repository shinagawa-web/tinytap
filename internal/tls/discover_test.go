package tls_test

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	tlsdiscover "github.com/shinagawa-web/tinytap/internal/tls"
)

// buildSharedLib compiles a real ELF shared library exporting the given
// function names as empty stub symbols. Testing against a compiler-produced
// ELF file (rather than a hand-rolled one) is what actually exercises
// debug/elf's dynamic symbol table parsing.
func buildSharedLib(t *testing.T, dir, name string, symbols []string) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("cc not available, skipping ELF fixture test")
	}

	var src strings.Builder
	for _, s := range symbols {
		fmt.Fprintf(&src, "void %s(void) {}\n", s)
	}
	if src.Len() == 0 {
		src.WriteString("int tinytap_fixture_placeholder;\n")
	}
	srcPath := filepath.Join(dir, name+".c")
	if err := os.WriteFile(srcPath, []byte(src.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(dir, name+".so")
	cmd := exec.Command(cc, "-shared", "-fPIC", "-o", outPath, srcPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile fixture lib: %v\n%s", err, out)
	}
	return outPath
}

// buildObjectFile compiles a plain relocatable object file — a valid ELF
// that has no dynamic symbol table (SHT_DYNSYM), unlike a shared library.
// Used to exercise the "library found but has no dynamic symbols at all"
// path, as opposed to "found but missing specific symbols".
func buildObjectFile(t *testing.T, dir, name string) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("cc not available, skipping ELF fixture test")
	}

	srcPath := filepath.Join(dir, name+".c")
	if err := os.WriteFile(srcPath, []byte("void SSL_read(void) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(dir, name+".o")
	cmd := exec.Command(cc, "-c", "-o", outPath, srcPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile fixture object: %v\n%s", err, out)
	}
	return outPath
}

// fixture builds a minimal /proc tree: a maps file mapping libPath (the path
// as it would appear inside the traced process's own mount namespace) and,
// if libFile is non-empty, that file's bytes placed under
// <root>/<pid>/root/<libPath> — mirroring how /proc/<pid>/root resolves a
// containerized process's view of its own files.
func fixture(t *testing.T, pid uint32, mapsLines []string, libPath, libFile string) string {
	t.Helper()
	root := t.TempDir()
	procDir := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(procDir, "maps"), []byte(strings.Join(mapsLines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if libFile != "" {
		rootedPath := filepath.Join(procDir, "root", libPath)
		if err := os.MkdirAll(filepath.Dir(rootedPath), 0o755); err != nil {
			t.Fatal(err)
		}
		content, err := os.ReadFile(libFile)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rootedPath, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	return root
}

func mapsLine(path string) string {
	return fmt.Sprintf("7f0000000000-7f0000200000 r-xp 00000000 08:01 131099   %s", path)
}

func TestFind_Success(t *testing.T) {
	buildDir := t.TempDir()
	lib := buildSharedLib(t, buildDir, "libssl", tlsdiscover.RequiredSymbols)

	const libPath = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	root := fixture(t, 1234, []string{mapsLine(libPath)}, libPath, lib)

	got, err := tlsdiscover.Find(root, 1234)
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	want := filepath.Join(root, "1234", "root", libPath)
	if got.Path != want {
		t.Errorf("Find().Path = %q, want %q", got.Path, want)
	}
	if got.Pid != 1234 {
		t.Errorf("Find().Pid = %d, want 1234", got.Pid)
	}
}

func TestFind_NoLibSSLMapped(t *testing.T) {
	// A process linked only against libc — no TLS, or a statically linked
	// TLS stack (e.g. a Go binary) that never touches libssl.
	root := fixture(t, 42, []string{mapsLine("/lib/x86_64-linux-gnu/libc.so.6")}, "", "")

	_, err := tlsdiscover.Find(root, 42)
	if !errors.Is(err, tlsdiscover.ErrLibSSLNotFound) {
		t.Errorf("Find() error = %v, want ErrLibSSLNotFound", err)
	}
}

func TestFind_ProcessNotFound(t *testing.T) {
	root := t.TempDir() // no pid directories at all

	_, err := tlsdiscover.Find(root, 9999)
	if !errors.Is(err, tlsdiscover.ErrLibSSLNotFound) {
		t.Errorf("Find() error = %v, want ErrLibSSLNotFound", err)
	}
}

func TestFind_MissingSymbols(t *testing.T) {
	buildDir := t.TempDir()
	// A libssl-like library that only exports two of the three required
	// symbols — e.g. a non-standard or incomplete TLS provider.
	lib := buildSharedLib(t, buildDir, "libssl-partial", []string{"SSL_read", "SSL_write"})

	const libPath = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	root := fixture(t, 5555, []string{mapsLine(libPath)}, libPath, lib)

	_, err := tlsdiscover.Find(root, 5555)
	var symErr *tlsdiscover.SymbolError
	if !errors.As(err, &symErr) {
		t.Fatalf("Find() error = %v, want *SymbolError", err)
	}
	if len(symErr.Missing) != 1 || symErr.Missing[0] != "SSL_set_fd" {
		t.Errorf("SymbolError.Missing = %v, want [SSL_set_fd]", symErr.Missing)
	}

	const wantSubstr = "is missing required symbols [SSL_set_fd]"
	if got := symErr.Error(); !strings.Contains(got, wantSubstr) {
		t.Errorf("SymbolError.Error() = %q, want to contain %q", got, wantSubstr)
	}
}

func TestFind_NoDynamicSymbolTable(t *testing.T) {
	buildDir := t.TempDir()
	// A plain relocatable object file is a valid ELF but has no dynamic
	// symbol table at all — distinct from "missing specific symbols".
	obj := buildObjectFile(t, buildDir, "notashared")

	const libPath = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	root := fixture(t, 6666, []string{mapsLine(libPath)}, libPath, obj)

	_, err := tlsdiscover.Find(root, 6666)
	var symErr *tlsdiscover.SymbolError
	if !errors.As(err, &symErr) {
		t.Fatalf("Find() error = %v, want *SymbolError", err)
	}
	if len(symErr.Missing) != len(tlsdiscover.RequiredSymbols) {
		t.Errorf("SymbolError.Missing = %v, want all of %v", symErr.Missing, tlsdiscover.RequiredSymbols)
	}
}

func TestFind_LibraryFileUnreadable(t *testing.T) {
	// maps claims libssl is loaded, but no backing file exists under
	// <root>/<pid>/root — e.g. a race with process exit, or a permission
	// issue reading into another mount namespace.
	const libPath = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	root := fixture(t, 7777, []string{mapsLine(libPath)}, "", "")

	_, err := tlsdiscover.Find(root, 7777)
	if err == nil {
		t.Fatal("Find() error = nil, want an error for missing library file")
	}
	var symErr *tlsdiscover.SymbolError
	if errors.As(err, &symErr) {
		t.Errorf("Find() error = %v (*SymbolError), want a plain open error", err)
	}
}

func TestFind_DefaultRoot(t *testing.T) {
	pid := os.Getpid() // always readable by ourselves, unlike pid 1
	if _, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid)); err != nil {
		t.Skipf("own /proc/%d/maps not accessible in this environment: %v", pid, err)
	}
	// The test binary doesn't link libssl, so this just exercises the
	// "" -> "/proc" default-root path, same as proc.Lookup("", ...).
	_, _ = tlsdiscover.Find("", uint32(pid))
}

func TestFind_AnonymousMappingsIgnored(t *testing.T) {
	// Anonymous mappings (heap, stack, etc.) have no trailing path field and
	// must not be mistaken for a library match.
	root := fixture(t, 77, []string{
		"7f0000000000-7f0000021000 rw-p 00000000 00:00 0",
		"7ffee0000000-7ffee0021000 rw-p 00000000 00:00 0                          [stack]",
	}, "", "")

	_, err := tlsdiscover.Find(root, 77)
	if !errors.Is(err, tlsdiscover.ErrLibSSLNotFound) {
		t.Errorf("Find() error = %v, want ErrLibSSLNotFound", err)
	}
}

func TestFind_DeletedLibraryMapping(t *testing.T) {
	// The kernel appends " (deleted)" to the mapped path when the backing
	// file has been unlinked while still mapped — e.g. a package upgrade
	// replacing libssl.so under a long-running process. The path up to
	// that suffix must still resolve.
	buildDir := t.TempDir()
	lib := buildSharedLib(t, buildDir, "libssl", tlsdiscover.RequiredSymbols)

	const libPath = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	root := fixture(t, 8888, []string{mapsLine(libPath + " (deleted)")}, libPath, lib)

	got, err := tlsdiscover.Find(root, 8888)
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	want := filepath.Join(root, "8888", "root", libPath)
	if got.Path != want {
		t.Errorf("Find().Path = %q, want %q", got.Path, want)
	}
}

func TestFind_MapsFilePermissionDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: permission-denied test not applicable")
	}
	root := t.TempDir()
	procDir := filepath.Join(root, "999")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mapsPath := filepath.Join(procDir, "maps")
	if err := os.WriteFile(mapsPath, []byte(mapsLine("/usr/lib/x86_64-linux-gnu/libssl.so.3")), 0o000); err != nil {
		t.Fatal(err)
	}

	_, err := tlsdiscover.Find(root, 999)
	if errors.Is(err, tlsdiscover.ErrLibSSLNotFound) {
		t.Errorf("Find() error = %v, want a permission error, not ErrLibSSLNotFound", err)
	}
	if err == nil {
		t.Error("Find() error = nil, want a permission error")
	}
}

func TestFind_MapsFileScanError(t *testing.T) {
	// A single line longer than bufio.Scanner's default token buffer
	// deterministically triggers scanner.Err() (bufio.ErrTooLong), which
	// must not be swallowed and reported as ErrLibSSLNotFound.
	root := t.TempDir()
	procDir := filepath.Join(root, "111")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatal(err)
	}
	hugeLine := strings.Repeat("x", 1<<20)
	if err := os.WriteFile(filepath.Join(procDir, "maps"), []byte(hugeLine+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := tlsdiscover.Find(root, 111)
	if errors.Is(err, tlsdiscover.ErrLibSSLNotFound) {
		t.Errorf("Find() error = %v, want a scan error, not ErrLibSSLNotFound", err)
	}
	if err == nil {
		t.Error("Find() error = nil, want a scan error")
	}
}
