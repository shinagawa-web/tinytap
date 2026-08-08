// Package tls locates the OpenSSL/BoringSSL library used by a traced
// process — either a mapped shared library, or the process's own executable
// for TLS stacks that statically bundle OpenSSL (#268) — and confirms it
// exports the symbols tinytap needs to hook (SSL_read, SSL_write,
// SSL_set_fd) in order to capture TLS plaintext without reading OpenSSL's
// internal struct layout. See issue #144 for the full design rationale.
//
// This package is pure Go: it reads /proc and parses ELF files, with no
// eBPF or ringbuf dependencies, so it can be unit-tested without a kernel.
package tls

import (
	"bufio"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const defaultRoot = "/proc"

// RequiredSymbols are the libssl symbols tinytap hooks: SSL_read and
// SSL_write to capture plaintext, SSL_set_fd to correlate the SSL object
// with its underlying fd, and SSL_free to detect connection teardown for
// abandon detection (#173). All four are public API entry points, so
// resolving them by name is stable across OpenSSL/BoringSSL versions —
// tinytap never reads the internal SSL struct layout.
var RequiredSymbols = []string{"SSL_read", "SSL_write", "SSL_set_fd", "SSL_free"}

// ErrLibSSLNotFound means neither a mapped OpenSSL/BoringSSL shared library
// nor the process's own executable exports the symbols tinytap needs. This
// covers "not using TLS at all" and "using a statically linked TLS stack
// with no C ABI to hook" (e.g. Go's crypto/tls) — tinytap can't distinguish
// those, and doesn't need to: neither is traceable via uprobe. It does not
// cover a statically-linked-but-unstripped TLS stack such as Node.js's
// bundled OpenSSL (#268/#269): Find resolves that case via the process's
// own executable instead.
var ErrLibSSLNotFound = errors.New("libssl not found in process memory map")

var libsslPattern = regexp.MustCompile(`/libssl\.so(\.[0-9]+)*$`)

// SymbolError means a libssl-like library was found but doesn't export one
// or more of RequiredSymbols — most commonly a stripped or non-standard
// build. Discover returns this instead of guessing or falling back to
// struct-offset reads, so callers can report clearly why TLS capture isn't
// available for this process (see "Handling stripped binaries" in #144).
type SymbolError struct {
	Path    string
	Missing []string
}

func (e *SymbolError) Error() string {
	return fmt.Sprintf("libssl at %s is missing required symbols %v", e.Path, e.Missing)
}

// Discovery describes the libssl library found for a traced process.
type Discovery struct {
	Pid uint32
	// Path is the library's path as visible from the host filesystem —
	// resolved through the process's own /proc/<pid>/root, so a
	// containerized process (e.g. nginx in a docker-compose service) with
	// its own rootfs still resolves to a file tinytap can actually open.
	Path string
}

// Find locates the libssl library used by pid and confirms it exports
// RequiredSymbols. If no libssl.so* is mapped, it falls back to checking
// whether pid's own executable exports RequiredSymbols directly — true for
// TLS stacks that statically bundle OpenSSL without stripping it, such as
// Node.js's official and NodeSource builds (#268/#269).
//
// root is the /proc mount point; pass "" to use the live "/proc".
//
// Find returns ErrLibSSLNotFound if neither path yields a usable candidate,
// or a *SymbolError if a mapped libssl-named library was found but is
// missing required symbols.
func Find(root string, pid uint32) (Discovery, error) {
	if root == "" {
		root = defaultRoot
	}
	pidDir := filepath.Join(root, strconv.FormatUint(uint64(pid), 10))

	mappedPath, err := findLibSSLMapping(filepath.Join(pidDir, "maps"))
	if err == nil {
		hostPath := filepath.Join(pidDir, "root", mappedPath)
		if err := checkSymbols(hostPath); err != nil {
			return Discovery{}, err
		}
		return Discovery{Pid: pid, Path: hostPath}, nil
	}
	if !errors.Is(err, ErrLibSSLNotFound) {
		return Discovery{}, err
	}

	return findInOwnExecutable(pidDir, pid)
}

// findInOwnExecutable checks whether pid's own executable exports
// RequiredSymbols, for processes that statically bundle a TLS library
// instead of loading a separate libssl.so (#268). Unlike a mapped
// libssl-named library, there's no name-based signal that this executable
// is even meant to be a TLS library, so a failed check here — for any
// reason — is reported as the same ErrLibSSLNotFound as never finding a
// candidate at all, not a *SymbolError: otherwise every ordinary non-TLS
// process (a plain Go binary, a shell, ...) would get logged as "has libssl
// ... missing required symbols" by callers like cmd/tinytap's tlswatch.go.
func findInOwnExecutable(pidDir string, pid uint32) (Discovery, error) {
	exeLink := filepath.Join(pidDir, "exe")
	exePath, err := os.Readlink(exeLink)
	if err != nil {
		if os.IsNotExist(err) {
			return Discovery{}, ErrLibSSLNotFound
		}
		// A real failure (e.g. permission denied) is not the same as "no
		// exe to fall back to" and shouldn't be reported as such.
		return Discovery{}, fmt.Errorf("readlink %s: %w", exeLink, err)
	}
	exePath = strings.TrimSuffix(exePath, " (deleted)")

	hostPath := filepath.Join(pidDir, "root", exePath)
	if err := checkSymbols(hostPath); err != nil {
		var symErr *SymbolError
		if errors.As(err, &symErr) {
			return Discovery{}, ErrLibSSLNotFound
		}
		return Discovery{}, err
	}
	return Discovery{Pid: pid, Path: hostPath}, nil
}

// findLibSSLMapping scans a /proc/<pid>/maps file for the first mapped
// libssl.so path (as seen from inside the process's own mount namespace).
func findLibSSLMapping(mapsPath string) (string, error) {
	f, err := os.Open(mapsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrLibSSLNotFound
		}
		// A real failure (e.g. permission denied) is not the same as "no
		// libssl mapped" and shouldn't be reported as such.
		return "", fmt.Errorf("open %s: %w", mapsPath, err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// The pathname field starts at the first '/'; taking everything
		// from there (rather than the last whitespace-delimited field)
		// handles the " (deleted)" suffix the kernel appends when a mapped
		// library's file has since been unlinked (e.g. replaced by a
		// package upgrade while the process keeps running).
		idx := strings.IndexByte(line, '/')
		if idx < 0 {
			continue // anonymous mapping, no backing path
		}
		path := strings.TrimSuffix(line[idx:], " (deleted)")
		if libsslPattern.MatchString(path) {
			return path, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scan %s: %w", mapsPath, err)
	}
	return "", ErrLibSSLNotFound
}

// checkSymbols opens the ELF file at path — a libssl-named library or a
// process's own executable — and confirms it exports every symbol in
// RequiredSymbols via its dynamic symbol table.
func checkSymbols(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("open ELF at %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	syms, err := f.DynamicSymbols()
	if err != nil {
		return &SymbolError{Path: path, Missing: RequiredSymbols}
	}

	present := make(map[string]bool, len(syms))
	for _, s := range syms {
		present[s.Name] = true
	}

	var missing []string
	for _, want := range RequiredSymbols {
		if !present[want] {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		return &SymbolError{Path: path, Missing: missing}
	}
	return nil
}
