// Package config loads tinytap's TOML session settings — the file-based
// replacement for the --output/-v/--verbose flags (#217).
package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// encodeTOML is injected so tests can force an encode failure — the real
// encoder can't fail on Config's plain scalar/slice fields, so this branch
// is otherwise unreachable from Init's exported behavior.
var encodeTOML = func(w io.Writer, v any) error {
	return toml.NewEncoder(w).Encode(v)
}

// Config holds tinytap's session settings.
type Config struct {
	Output  string       `toml:"output"`
	Verbose bool         `toml:"verbose"`
	Filter  FilterConfig `toml:"filter"`
}

// FilterConfig narrows capture to specific processes. Not yet consumed by
// the BPF program — the schema exists so #211 can build directly on it.
type FilterConfig struct {
	PID  []uint32 `toml:"pid"`
	Comm []string `toml:"comm"`
}

// defaultConfig is a var (not a plain func) so tests can verify Init()
// preserves whatever it returns instead of clobbering it.
var defaultConfig = func() Config {
	return Config{Output: "auto"}
}

// Load resolves, decodes, and validates tinytap's config file.
//
// If path is non-empty (an explicit --config override), that file is used
// and it is an error for it not to exist. Otherwise Load searches
// ./tinytap.toml, then $XDG_CONFIG_HOME/tinytap/config.toml (falling back
// to ~/.config/tinytap/config.toml) — finding neither is not an error, the
// built-in defaults apply.
func Load(path string) (Config, error) {
	if path == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return Config{}, fmt.Errorf("getwd: %w", err)
		}
		home, _ := os.UserHomeDir() // best-effort; "" just drops that candidate
		found, err := find(cwd, os.Getenv("XDG_CONFIG_HOME"), home)
		if err != nil {
			return Config{}, err
		}
		if found == "" {
			return defaultConfig(), nil
		}
		path = found
	} else if _, err := os.Stat(path); err != nil {
		return Config{}, fmt.Errorf("--config %s: %w", path, err)
	}

	cfg := defaultConfig()
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Init writes a fully-populated default config file to path, so that
// `tinytap config init && tinytap` just works with no further edits.
// Refuses to overwrite an existing file unless force is true.
//
// Generated from the same Config/FilterConfig structs Load decodes into
// (via toml.Encoder), rather than a hand-maintained string template, so the
// written file can't drift from the real schema when a field is added.
func Init(path string, force bool) error {
	if !force {
		ok, err := exists(path)
		if err != nil {
			return err
		}
		if ok {
			return fmt.Errorf("%s already exists (use --force to overwrite)", path)
		}
	}

	cfg := defaultConfig()
	// Normalize nil slices to empty so the encoder writes "pid = []" /
	// "comm = []" instead of omitting the keys entirely — the file should
	// show every key, even ones defaulting to empty. Only the nil case is
	// touched, so this can't clobber a non-nil default defaultConfig()
	// might set in the future.
	if cfg.Filter.PID == nil {
		cfg.Filter.PID = []uint32{}
	}
	if cfg.Filter.Comm == nil {
		cfg.Filter.Comm = []string{}
	}

	var buf bytes.Buffer
	buf.WriteString("# tinytap config file — see README.md's Configuration section for field docs.\n\n")
	if err := encodeTOML(&buf, cfg); err != nil {
		return fmt.Errorf("encode default config: %w", err)
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// find returns the first existing candidate in the search order, or "" if
// none exist. Returns an error if a candidate can't be stat'd for a reason
// other than not existing (e.g. permission denied on a parent directory) —
// that should surface as a real error, not silently fall through to
// defaults. A pure function of its inputs so the search order is testable
// without touching the real cwd, env, or home directory.
func find(cwd, xdgConfigHome, home string) (string, error) {
	if cwd != "" {
		p := filepath.Join(cwd, "tinytap.toml")
		ok, err := exists(p)
		if err != nil {
			return "", err
		}
		if ok {
			return p, nil
		}
	}
	if xdgConfigHome == "" && home != "" {
		xdgConfigHome = filepath.Join(home, ".config")
	}
	if xdgConfigHome != "" {
		p := filepath.Join(xdgConfigHome, "tinytap", "config.toml")
		ok, err := exists(p)
		if err != nil {
			return "", err
		}
		if ok {
			return p, nil
		}
	}
	return "", nil
}

// exists reports whether path is stat-able. A "not found" error is not
// exceptional — it just means this candidate isn't the one — but any other
// error (permission denied, I/O error) is returned so the caller can
// surface it instead of silently treating it as "doesn't exist".
func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func (c Config) validate() error {
	switch c.Output {
	case "auto", "stdout", "tui":
	default:
		return fmt.Errorf("invalid output %q: want auto, stdout, or tui", c.Output)
	}
	return nil
}
