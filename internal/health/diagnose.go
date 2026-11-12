package health

import (
	"fmt"

	"egress/internal/core"
	"io"
	"os"

	"egress/internal/logx"
	"egress/internal/platform"
	"egress/internal/split"
)

// writeDiagnose renders the state that explains a failed first run. It lives
// here so reports and the CLI share one renderer.
func WriteDiagnose(w io.Writer) error {
	fmt.Fprintln(w, "egress")
	if exe, err := os.Executable(); err == nil {
		fmt.Fprintf(w, "  executable: %s\n", exe)
	}
	fmt.Fprintf(w, "  debug: %v\n", logx.DebugEnabled())
	if path := platform.LogPath(); path != "" {
		fmt.Fprintf(w, "  log: %s\n", path)
	}
	fmt.Fprintln(w, "  (run as root/Administrator for the WireGuard and listener sections)")
	if err := platform.Diagnose(w); err != nil {
		return err
	}
	fmt.Fprintln(w, "\n== split ==")
	for _, line := range split.ProfileSummary(split.ProfileDir()) {
		fmt.Fprintf(w, "  %s\n", line)
	}
	for _, line := range split.OverrideSummary(split.ProfileDir()) {
		fmt.Fprintf(w, "  %s\n", line)
	}
	return nil
}

// buildVersion is the running build, empty when the linker did not set it.
func buildVersion() string {
	if core.BuildVersion != "" {
		return core.BuildVersion
	}
	return "0.0.0"
}
