//go:build windows

package winlog

import (
	"fmt"
	"os/exec"
	"strings"
)

// EnsureSource registers the Application log source once. Install has the
// rights; every later caller only writes.
func EnsureSource() {
	_, _ = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"if (-not [System.Diagnostics.EventLog]::SourceExists('egress')) { New-EventLog -LogName Application -Source 'egress' }",
	).CombinedOutput()
}

// Notify writes one Application log entry. Best effort by design: a missing
// event log must never fail an install or an update.
func Notify(level, message string) {
	entry := "Information"
	switch strings.ToLower(level) {
	case "error":
		entry = "Error"
	case "warning", "warn":
		entry = "Warning"
	}
	msg := strings.ReplaceAll(message, "'", "''")
	script := fmt.Sprintf(
		`try { Write-EventLog -LogName Application -Source 'egress' -EventId 1 -EntryType %s -Message '%s' } catch {}`,
		entry, msg)
	_, _ = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
}
