// Package tls locates the OpenSSL/BoringSSL shared library loaded by a
// traced process and confirms it exports the symbols tinytap needs to hook
// (SSL_read, SSL_write, SSL_set_fd) in order to capture TLS plaintext
// without reading OpenSSL's internal struct layout. See issue #144 for the
// full design rationale.
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
// SSL_write to capture plaintext, and SSL_set_fd to correlate the SSL
// object with its underlying fd. All three are public API entry points, so
// resolving them by name is stable across OpenSSL/BoringSSL versions —
// tinytap never reads the internal SSL struct layout.
var RequiredSymbols = []string{"SSL_read", "SSL_write", "SSL_set_fd"}

// ErrLibSSLNotFound means the process has no OpenSSL/BoringSSL shared
// library mapped. This covers both "not using TLS at all" and "using a
// statically linked TLS stack that never calls into a separate libssl"
// (e.g. Go's crypto/tls) — tinytap can't distinguish the two from the
// memory map alone, and doesn't need to: neither case is traceable via
// uprobe on libssl.
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
// RequiredSymbols.
//
// root is the /proc mount point; pass "" to use the live "/proc".
//
// Find returns ErrLibSSLNotFound if the process has no libssl mapped, or a
// *SymbolError if the library is mapped but missing required symbols.
func Find(root string, pid uint32) (Discovery, error) {
	if root == "" {
		root = defaultRoot
	}
	pidDir := filepath.Join(root, strconv.FormatUint(uint64(pid), 10))

	mappedPath, err := findLibSSLMapping(filepath.Join(pidDir, "maps"))
	if err != nil {
		return Discovery{}, err
	}

	hostPath := filepath.Join(pidDir, "root", mappedPath)
	if err := checkSymbols(hostPath); err != nil {
		return Discovery{}, err
	}

	return Discovery{Pid: pid, Path: hostPath}, nil
}

// findLibSSLMapping scans a /proc/<pid>/maps file for the first mapped
// libssl.so path (as seen from inside the process's own mount namespace).
func findLibSSLMapping(mapsPath string) (string, error) {
	f, err := os.Open(mapsPath)
	if err != nil {
		return "", ErrLibSSLNotFound
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue // anonymous mapping, no backing path
		}
		path := fields[len(fields)-1]
		if libsslPattern.MatchString(path) {
			return path, nil
		}
	}
	return "", ErrLibSSLNotFound
}

// checkSymbols opens the ELF file at path and confirms it exports every
// symbol in RequiredSymbols via its dynamic symbol table.
func checkSymbols(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("open libssl ELF at %s: %w", path, err)
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
