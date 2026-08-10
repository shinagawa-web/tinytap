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

var RequiredSymbols = []string{"SSL_read", "SSL_write", "SSL_set_fd", "SSL_free"}

var ErrLibSSLNotFound = errors.New("libssl not found for process")

var libsslPattern = regexp.MustCompile(`/libssl\.so(\.[0-9]+)*$`)

type SymbolError struct {
	Path    string
	Missing []string
}

func (e *SymbolError) Error() string {
	return fmt.Sprintf("libssl at %s is missing required symbols %v", e.Path, e.Missing)
}

type Discovery struct {
	Pid  uint32
	Path string
}

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

func findInOwnExecutable(pidDir string, pid uint32) (Discovery, error) {
	exeLink := filepath.Join(pidDir, "exe")
	exePath, err := os.Readlink(exeLink)
	if err != nil {
		if os.IsNotExist(err) {
			return Discovery{}, ErrLibSSLNotFound
		}
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

func findLibSSLMapping(mapsPath string) (string, error) {
	f, err := os.Open(mapsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrLibSSLNotFound
		}
		return "", fmt.Errorf("open %s: %w", mapsPath, err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.IndexByte(line, '/')
		if idx < 0 {
			continue
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
