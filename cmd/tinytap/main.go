package main

import (
	"errors"
	"fmt"
	"os"
)

var osExit = os.Exit
var runner = run

var errSilentExit = errors.New("silent exit")

func main() {
	if err := runner(); err != nil {
		if !errors.Is(err, errSilentExit) {
			fmt.Fprintln(os.Stderr, err)
		}
		osExit(1)
	}
}
