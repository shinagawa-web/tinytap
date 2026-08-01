// Package config loads tinytap's TOML session settings — the file-based
// replacement for the --output/-v/--verbose flags (#217).
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

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

func defaultConfig() Config {
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
		path = find(cwd, os.Getenv("XDG_CONFIG_HOME"), home)
		if path == "" {
			return defaultConfig(), nil
		}
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

// find returns the first existing candidate in the search order, or "" if
// none exist. A pure function of its inputs so the search order is
// testable without touching the real cwd, env, or home directory.
func find(cwd, xdgConfigHome, home string) string {
	if cwd != "" {
		if p := filepath.Join(cwd, "tinytap.toml"); exists(p) {
			return p
		}
	}
	if xdgConfigHome == "" && home != "" {
		xdgConfigHome = filepath.Join(home, ".config")
	}
	if xdgConfigHome != "" {
		if p := filepath.Join(xdgConfigHome, "tinytap", "config.toml"); exists(p) {
			return p
		}
	}
	return ""
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (c Config) validate() error {
	switch c.Output {
	case "auto", "stdout", "tui":
	default:
		return fmt.Errorf("invalid output %q: want auto, stdout, or tui", c.Output)
	}
	return nil
}
