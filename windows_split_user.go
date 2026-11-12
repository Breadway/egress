//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// splitUserTask is the one-shot task that applies the per-user half of split
// mode inside the logged-in user's session. It exists because an update runs
// install as SYSTEM, where HKCU belongs to SYSTEM and a tray would start in
// session 0.
const splitUserTask = "egress-split-user"

const (
	proxyListenAddr = "127.0.0.1:1080"
	pacURL          = "http://127.0.0.1:1081/proxy.pac"
)

// runningAsSystem reports whether this process was started by the task
// scheduler as SYSTEM rather than by a person in an elevated prompt.
func runningAsSystem() bool {
	return strings.EqualFold(os.Getenv("USERNAME"), "SYSTEM")
}

// consoleUser returns the account logged on at the console, or an empty string
// when nobody is. A session-0 process has no other way to name it.
func consoleUser() (string, error) {
	out, err := powershell(`(Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName`)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// runSplitUserTask runs the per-user setup in user's session and waits for it.
func runSplitUserTask(user, exe, authPath string) error {
	// Windows paths go inside plain double quotes: %q would double the
	// backslashes and hand the child a path that does not exist.
	args := fmt.Sprintf(`split-user --exe "%s" --auth "%s"`, exe, authPath)
	script, err := windowsTaskScript(splitUserTask, exe, args,
		"New-ScheduledTaskTrigger -Once -At (Get-Date)", userPrincipal(user), false)
	if err != nil {
		return err
	}
	if _, err := powershell(script); err != nil {
		return fmt.Errorf("register per-user setup task: %w", err)
	}
	defer exec.Command("schtasks", "/delete", "/tn", splitUserTask, "/f").Run()

	if out, err := exec.Command("schtasks", "/run", "/tn", splitUserTask).CombinedOutput(); err != nil {
		return fmt.Errorf("run per-user setup task: %v: %s", err, strings.TrimSpace(string(out)))
	}
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		out, _ := exec.Command("schtasks", "/query", "/tn", splitUserTask, "/fo", "list").Output()
		status, result := taskState(string(out))
		if status != "" && !strings.EqualFold(status, "Running") {
			if result != "" && result != "0" {
				return fmt.Errorf("per-user setup task failed with result %s", result)
			}
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New("per-user setup task did not finish")
}

// taskState pulls the status and last result out of schtasks list output.
func taskState(out string) (status, result string) {
	for _, line := range strings.Split(out, "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(name) {
		case "Status":
			status = strings.TrimSpace(value)
		case "Last Result":
			result = strings.TrimSpace(value)
		}
	}
	return status, result
}

// cmdSplitUser applies the per-user proxy settings and starts the tray. The
// scheduled task calls it inside the user's session.
func cmdSplitUser(args []string) error {
	fs := newFlagSet("split-user")
	exePath := fs.String("exe", "", "installed executable")
	authPath := fs.String("auth", "", "SOCKS auth file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *exePath == "" || *authPath == "" {
		return errors.New("missing --exe or --auth")
	}
	// The task gives this process no console, so a debug build must log to
	// the shared file for the failure to be visible at all.
	setupLogging(resolveDebug(false))
	if err := applyUserSplit(*exePath, *authPath); err != nil {
		appLogger().Printf("split-user: %v", err)
		return err
	}
	return nil
}
