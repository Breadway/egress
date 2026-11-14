//go:build windows

package egress

import (
	"egress/internal/split"
	"egress/internal/update"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// stagedReleaseFile returns the staged binary for this release when one is
// already on disk and intact. Without this a task that never ran would make
// the update timer download twenty megabytes every minute.
func stagedReleaseFile(m update.Manifest) string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		return ""
	}
	path := filepath.Join(programData, "egress", "updates", m.Version, "egress.exe")
	info, err := os.Stat(path)
	if err != nil || info.Size() != m.Size {
		return ""
	}
	sum, err := fileSHA256(path)
	if err != nil || sum != m.SHA256 {
		return ""
	}
	return path
}

// stageWindowsRelease puts the verified release under ProgramData and asks the
// task scheduler to apply it. Windows locks a running executable, so the
// replacement has to happen after this process exits.
func stageWindowsRelease(base string, m update.Manifest) error {
	staged := stagedReleaseFile(m)
	if staged == "" {
		src, err := downloadRelease(base, m)
		if err != nil {
			return err
		}
		defer os.Remove(src)
		if staged, err = stageWindowsBinary(m, src); err != nil {
			return err
		}
	} else {
		debugf("release %s is already staged at %s", m.Version, staged)
	}
	return runWindowsUpdateTask(m, staged)
}

// stageWindowsBinary copies a verified release to its staging directory.
func stageWindowsBinary(m update.Manifest, src string) (string, error) {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		return "", errors.New("ProgramData is not set")
	}
	dir := filepath.Join(programData, "egress", "updates", m.Version)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	staged := filepath.Join(dir, "egress.exe")
	if err := copyExecutable(src, staged); err != nil {
		return "", fmt.Errorf("stage binary: %w", err)
	}
	return staged, nil
}

// runWindowsUpdateTask registers and starts the task that applies the staged
// release after this process exits.
func runWindowsUpdateTask(m update.Manifest, staged string) error {
	splitArg := ""
	if split.Enabled() {
		splitArg = " --split"
	}
	// Run the staged binary directly rather than through a .cmd shim:
	// New-ScheduledTaskAction takes the executable and its arguments
	// separately, so no shell quoting is involved.
	applyArgs := fmt.Sprintf(`update-apply --staged "%s" --task %s --sha %s --delay 8s%s`,
		staged, windowsUpdateTask, m.SHA256, splitArg)
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
	return nil
}
