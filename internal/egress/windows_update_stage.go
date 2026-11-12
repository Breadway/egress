//go:build windows

package egress

import (
	"egress/internal/update"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// stageWindowsUpdate copies the verified release under ProgramData and asks the
// task scheduler to apply it. Windows locks a running executable, so the
// replacement has to happen after this process exits.
func stageWindowsUpdate(m update.Manifest, stagedSource string) error {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		return errors.New("ProgramData is not set")
	}
	dir := filepath.Join(programData, "egress", "updates", m.Version)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	staged := filepath.Join(dir, "egress.exe")
	if err := copyExecutable(stagedSource, staged); err != nil {
		return fmt.Errorf("stage binary: %w", err)
	}
	splitArg := ""
	if splitEnabled() {
		splitArg = " --split"
	}
	// Run the staged binary directly rather than through a .cmd shim:
	// New-ScheduledTaskAction takes the executable and its arguments
	// separately, so no shell quoting is involved.
	applyArgs := fmt.Sprintf(`update-apply --staged "%s" --task %s --delay 8s%s`,
		staged, windowsUpdateTask, splitArg)
	taskScript, err := windowsTaskScript(windowsUpdateTask, staged, applyArgs, winTriggerLogon, systemPrincipal, false)
	if err != nil {
		return err
	}
	if _, err := powershell(taskScript); err != nil {
		return fmt.Errorf("create update task: %w", err)
	}
	out, err := exec.Command("schtasks", "/run", "/tn", windowsUpdateTask).CombinedOutput()
	if err != nil {
		return fmt.Errorf("run update task: %v: %s", err, strings.TrimSpace(string(out)))
	}
	fmt.Println("update staged; the scheduled task will apply it in a few seconds")
	return nil
}
