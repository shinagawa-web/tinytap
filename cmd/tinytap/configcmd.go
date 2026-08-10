package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/shinagawa-web/tinytap/internal/config"
)

var configInit = config.Init

func runConfigCmd(args []string) error {
	if len(args) == 0 || args[0] != "init" {
		return errors.New("usage: tinytap config init [path]")
	}
	return runConfigInit(args[1:])
}

func runConfigInit(args []string) error {
	fs := flag.NewFlagSet("tinytap config init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configFlag := fs.String("config", "", "path to write (default: ./tinytap.toml)")
	force := fs.Bool("force", false, "overwrite an existing config file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := "tinytap.toml"
	if *configFlag != "" {
		path = *configFlag
	}
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}

	if err := configInit(path, *force); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", path)
	return nil
}
