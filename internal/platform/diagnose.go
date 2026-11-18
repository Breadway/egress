package platform

import (
	"context"
	"io"
	"os/exec"
	"strings"
	"time"
)

// diagnoseCommandTimeout keeps one wedged command from hanging the whole
// report. Every probe is read-only and local, so this is generous.
const diagnoseCommandTimeout = 20 * time.Second

// diagnoseOutputLimit caps a single command's contribution; schtasks /v alone
// is worth several kilobytes.
const diagnoseOutputLimit = 12 << 10

func section(w io.Writer, name string) {
	_, _ = io.WriteString(w, "\n== "+name+" ==\n")
}

// show runs one command and prints its output. It used to print only the
// command line, which made every diagnose report and support bundle a list of
// commands with no answers in it, so a reader could not tell a working install
// from a broken one.
func show(w io.Writer, name string, args ...string) {
	cmdline := name
	for _, a := range args {
		cmdline += " " + a
	}
	_, _ = io.WriteString(w, "$ "+cmdline+"\n")

	ctx, cancel := context.WithTimeout(context.Background(), diagnoseCommandTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	text := strings.TrimRight(string(out), "\r\n")
	if text != "" {
		if len(text) > diagnoseOutputLimit {
			text = text[:diagnoseOutputLimit] + "\n  (truncated)"
		}
		for _, line := range strings.Split(text, "\n") {
			_, _ = io.WriteString(w, "  "+strings.TrimRight(line, "\r")+"\n")
		}
	}
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		_, _ = io.WriteString(w, "  (timed out)\n")
	case err != nil:
		_, _ = io.WriteString(w, "  ("+err.Error()+")\n")
	}
}
