package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/shinagawa-web/tinytap/internal/config"
	"github.com/shinagawa-web/tinytap/internal/drops"
	"github.com/shinagawa-web/tinytap/internal/output"
	"github.com/shinagawa-web/tinytap/internal/output/stdout"
	"github.com/shinagawa-web/tinytap/internal/output/tui"
)

type appConfig struct {
	configPath  string
	showVersion bool
}

func parseFlags(args []string) (appConfig, error) {
	fs := flag.NewFlagSet("tinytap", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "", "path to config file (default: ./tinytap.toml, then $XDG_CONFIG_HOME/tinytap/config.toml)")
	showVersion := fs.Bool("version", false, "print version, commit, and build date, then exit")
	if err := fs.Parse(args); err != nil {
		return appConfig{}, err
	}
	return appConfig{configPath: *configPath, showVersion: *showVersion}, nil
}

type bpfSession interface {
	Close() error
	reader() ringbufCloser
	dropCounts() drops.Counts
}

type tuiSink interface {
	output.Sink
	Run() error
	Quit()
	SendDiag(line string)
}

type tuiRunner interface {
	Run() error
	Quit()
}

var (
	loadBPF       func(pid uint32) (bpfSession, error)
	isTerminalFn                                           = term.IsTerminal
	getSizeFn                                              = term.GetSize
	newTUISink    func(w, h int) tuiSink                   = defaultNewTUISink
	newStdoutSink func(verbose bool) output.Sink           = defaultNewStdoutSink
	doRunStdout   func(bpfSession, bool)                   = runStdout
	doRunTUI      func(bpfSession, int, int)               = runTUI
	loadConfig    func(path string) (config.Config, error) = config.Load
)

func defaultNewTUISink(w, h int) tuiSink            { return tui.New(w, h) }
func defaultNewStdoutSink(verbose bool) output.Sink { return stdout.New(verbose) }

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "config" {
		return runConfigCmd(os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == "doctor" {
		return runDoctorCmd()
	}

	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		return err
	}
	if cfg.showVersion {
		printVersion()
		return nil
	}

	conf, err := loadConfig(cfg.configPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	decision, w, h := decideOutput(conf.Output, isTerminalFn, getSizeFn)
	if decision == outputExit {
		return errSilentExit
	}

	tt, err := loadBPF(uint32(os.Getpid()))
	if err != nil {
		return classifyLoadError(err)
	}
	defer func() {
		if err := tt.Close(); err != nil {
			log.Printf("teardown: %v", err)
		}
	}()

	if decision == outputTUI {
		doRunTUI(tt, w, h)
	} else {
		doRunStdout(tt, conf.Verbose)
	}
	return nil
}

func closeOnInterrupt(rd io.Closer, stop <-chan os.Signal) {
	go func() {
		<-stop
		if err := rd.Close(); err != nil {
			log.Printf("close reader: %v", err)
		}
	}()
}

func runStdout(sess bpfSession, verbose bool) {
	rd := sess.reader()
	sink := newSSLWatcher(newStdoutSink(verbose))
	defer closeSink(sink)
	log.Printf("tinytap running (version %s) — watching accept4/read/write/close/recvfrom/sendto/recvmsg/sendmsg. Press Ctrl-C to stop.", version)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)
	closeOnInterrupt(rd, stop)
	capture(rd, sink)
	reportDrops(sess, sink)
}

func runCapturePipeline(rd ringbufCloser, sink output.Sink, ui tuiRunner) error {
	done := make(chan struct{})
	go func() {
		capture(rd, sink)
		close(done)
		ui.Quit()
	}()
	runErr := ui.Run()
	if err := rd.Close(); err != nil {
		log.Printf("close reader: %v", err)
	}
	<-done
	return runErr
}

func runTUI(sess bpfSession, width, height int) {
	rd := sess.reader()
	tuiS := newTUISink(width, height)
	sink := newSSLWatcher(tuiS)
	defer closeSink(sink)

	diag := newDiagBuffer(tuiS.SendDiag, isRoutineTLSAttach)
	prev := log.Writer()
	log.SetOutput(diag)

	runErr := runCapturePipeline(rd, sink, sink)

	log.SetOutput(prev)
	diag.Flush(os.Stderr)
	if runErr != nil {
		log.Printf("tui: %v", runErr)
	}
	reportDrops(sess, sink)
}

func isRoutineTLSAttach(line string) bool {
	return strings.Contains(line, "uprobe attached for pid") ||
		strings.Contains(line, "uprobes attached for pid")
}

func closeSink(sink output.Sink) {
	if err := sink.Close(); err != nil {
		log.Printf("sink close: %v", err)
	}
}

func reportDrops(sess bpfSession, w *sslWatcher) {
	if s := sess.dropCounts().Add(w.dropCounts()).Summary(); s != "" {
		log.Print(s)
	}
}
