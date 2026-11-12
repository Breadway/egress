package egress

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"

	"egress/internal/logx"
	"egress/internal/split"
)

func appLogger() *log.Logger { return logx.Logger() }

func closeLog() { logx.Close() }

func setupLogging(debug bool) { logx.Setup(debug, logPath()) }

func debugf(format string, args ...any) { logx.Debugf(format, args...) }

func truncate(s string, max int) string { return logx.Truncate(s, max) }

func execLogged(name string, args ...string) ([]byte, error) { return logx.ExecLogged(name, args...) }

func runLogged(name string, args ...string) error { return logx.RunLogged(name, args...) }

// diagnose collects the state needed to explain a failed first run.
func diagnose() error {
	return writeDiagnose(os.Stdout)
}

func writeDiagnose(w io.Writer) error {
	fmt.Fprintln(w, "egress")
	if exe, err := os.Executable(); err == nil {
		fmt.Fprintf(w, "  executable: %s\n", exe)
	}
	fmt.Fprintf(w, "  debug: %v\n", logx.DebugEnabled())
	if path := logPath(); path != "" {
		fmt.Fprintf(w, "  log: %s\n", path)
	}
	fmt.Fprintln(w, "  (run as root/Administrator for the WireGuard and listener sections)")
	if err := writeDiagnosePlatform(w); err != nil {
		return err
	}
	section(w, "split")
	for _, line := range split.ProfileSummary(split.ProfileDir()) {
		fmt.Fprintf(w, "  %s\n", line)
	}
	for _, line := range split.OverrideSummary(split.ProfileDir()) {
		fmt.Fprintf(w, "  %s\n", line)
	}
	return nil
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
