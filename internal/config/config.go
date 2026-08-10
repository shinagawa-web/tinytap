package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

var encodeTOML = func(w io.Writer, v any) error {
	return toml.NewEncoder(w).Encode(v)
}

type Config struct {
	Output  string `toml:"output"`
	Verbose bool   `toml:"verbose"`
}

func defaultConfig() Config {
	return Config{Output: "auto"}
}

func Load(path string) (Config, error) {
	if path == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return Config{}, fmt.Errorf("getwd: %w", err)
		}
		home, _ := os.UserHomeDir()
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
