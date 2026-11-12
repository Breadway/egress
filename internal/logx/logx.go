// Package logx owns the process logger and the logged command wrappers. It
// lives below platform so the platform layer can trace commands without
// importing the CLI package.
package logx

import (
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

var (
	logger       = log.New(os.Stderr, "egress: ", log.LstdFlags)
	debugEnabled bool
	logFile      *os.File
)

// DebugEnabled reports whether tracing is on.
func DebugEnabled() bool { return debugEnabled }

// Logger is the process logger.
func Logger() *log.Logger { return logger }

// Close detaches the log file so Remove can delete it. On Windows an open
// handle keeps the file locked.
func Close() {
	if logFile == nil {
		return
	}
	logger.SetOutput(os.Stderr)
	_ = logFile.Close()
	logFile = nil
}

// Setup turns on verbose tracing. Everything still goes to stderr, and when a
// log path is given it also goes to a file, because the boot service on
// Windows runs detached and has nowhere to send output otherwise.
func Setup(debug bool, path string) {
	if !debug {
		return
	}
	debugEnabled = true
	logger.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if path == "" {
		return
	}
	if err := os.MkdirAll(dir(path), 0700); err != nil {
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

// Debugf logs only when tracing is on.
func Debugf(format string, args ...any) {
	if !debugEnabled {
		return
	}
	logger.Printf(format, args...)
}

// Truncate shortens s to max characters, marking the cut.
func Truncate(s string, max int) string {
	if len(s) <= max || max <= 0 {
		return s
	}
	return s[:max] + "..."
}

// ExecLogged runs a command and traces it when debugging.
func ExecLogged(name string, args ...string) ([]byte, error) {
	start := time.Now()
	out, err := exec.Command(name, args...).CombinedOutput()
	if debugEnabled {
		debugf("exec: %s %s", name, strings.Join(args, " "))
		debugf("exec: exit=%v took=%s output=%q", err, time.Since(start).Round(time.Millisecond), Truncate(string(out), 4000))
	}
	return out, err
}

// RunLogged runs a command, traces it, and discards its output.
func RunLogged(name string, args ...string) error {
	_, err := ExecLogged(name, args...)
	return err
}

// debugf is the internal short form.
func debugf(format string, args ...any) {
	if !debugEnabled {
		return
	}
	logger.Printf(format, args...)
}

func dir(path string) string {
	if i := strings.LastIndexAny(path, `/\`); i > 0 {
		return path[:i]
	}
	return "."
}

// Tail writes the last n lines of the log file, for diagnose and reports.
func Tail(w io.Writer, path string, lines int) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	parts := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	for _, line := range parts {
		_, _ = io.WriteString(w, line+"\n")
	}
}
