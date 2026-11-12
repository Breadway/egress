package egress

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var (
	logger       = log.New(os.Stderr, "egress: ", log.LstdFlags)
	debugEnabled bool
	logFile      *os.File
)

func appLogger() *log.Logger { return logger }

// closeLog detaches the log file so Remove can delete it. On Windows an open
// handle keeps the file locked.
func closeLog() {
	if logFile == nil {
		return
	}
	logger.SetOutput(os.Stderr)
	_ = logFile.Close()
	logFile = nil
}

// setupLogging turns on verbose tracing. Everything still goes to stderr, and
// when a log path is available it also goes to a file, because the boot service
// on Windows runs detached and has nowhere to send output otherwise.
func setupLogging(debug bool) {
	if !debug {
		return
	}
	debugEnabled = true
	logger.SetFlags(log.LstdFlags | log.Lmicroseconds)

	path := logPath()
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		logger.Printf("debug: cannot create log directory: %v", err)
		return
	}
	if info, err := os.Stat(path); err == nil && info.Size() > 5<<20 {
		_ = os.Rename(path, path+".old")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		logger.Printf("debug: cannot open %s: %v", path, err)
		return
	}
	logFile = file
	logger.SetOutput(io.MultiWriter(os.Stderr, file))
	logger.Printf("debug mode on, log file %s", path)
}

func debugf(format string, args ...any) {
	if !debugEnabled {
		return
	}
	logger.Printf(format, args...)
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// execLogged runs a command, tracing it and its output when debug is on.
func execLogged(name string, args ...string) ([]byte, error) {
	debugf("exec: %s %s", name, strings.Join(args, " "))
	start := time.Now()
	out, err := exec.Command(name, args...).CombinedOutput()
	debugf("exec: exit=%v took=%s output=%q",
		err, time.Since(start).Round(time.Millisecond), truncate(string(out), 2000))
	return out, err
}

// runLogged is execLogged with a useful error message on failure.
func runLogged(name string, args ...string) error {
	out, err := execLogged(name, args...)
	if err != nil {
		return fmt.Errorf("%s %s: %v (%s)", name, strings.Join(args, " "), err, truncate(string(out), 400))
	}
	return nil
}

// diagnose collects the state needed to explain a failed first run.
func diagnose() error {
	return writeDiagnose(os.Stdout)
}

func writeDiagnose(w io.Writer) error {
	fmt.Fprintln(w, "egress")
	if exe, err := os.Executable(); err == nil {
		fmt.Fprintf(w, "  executable: %s\n", exe)
	}
	fmt.Fprintf(w, "  debug: %v\n", debugEnabled)
	if path := logPath(); path != "" {
		fmt.Fprintf(w, "  log: %s\n", path)
	}
	fmt.Fprintln(w, "  (run as root/Administrator for the WireGuard and listener sections)")
	return writeDiagnosePlatform(w)
}

func section(w io.Writer, name string) {
	fmt.Fprintf(w, "\n== %s ==\n", name)
}

func show(w io.Writer, name string, args ...string) {
	out, err := exec.Command(name, args...).CombinedOutput()
	fmt.Fprintf(w, "$ %s %s\n", name, strings.Join(args, " "))
	fmt.Fprint(w, string(out))
	if err != nil {
		fmt.Fprintf(w, "(exit: %v)\n", err)
	}
}

func tailLog(w io.Writer, lines int) {
	path := logPath()
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(w, "  no log at %s: %v\n", path, err)
		return
	}
	parts := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	fmt.Fprintln(w, strings.Join(parts, "\n"))
}
