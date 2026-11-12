package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const windowsUpdateTask = "egress-update"

// installedExePath is the permanent location the scheduled task runs.
func installedExePath() (string, error) {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			return "", errors.New("ProgramData is not set")
		}
		return filepath.Join(programData, "egress", "egress.exe"), nil
	}
	return os.Executable()
}

// windowsUpdateTaskArgs creates a one-shot task that runs the staged apply
// script as SYSTEM. /sc onlogon avoids locale-dependent date parsing; the task
// is run immediately and deleted by the apply step, and /f overwrites any
// leftover.
func windowsUpdateTaskArgs(task, script string) []string {
	return []string{
		"/create", "/tn", task, "/tr", script, "/sc", "onlogon",
		"/ru", "SYSTEM", "/rl", "HIGHEST", "/f",
	}
}

// stageWindowsUpdate copies the verified release under ProgramData and asks the
// task scheduler to apply it. Windows locks a running executable, so the
// replacement has to happen after this process exits.
func stageWindowsUpdate(m UpdateManifest, stagedSource string) error {
	if runtime.GOOS != "windows" {
		return errors.New("Windows update staging called on another platform")
	}
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
	script := filepath.Join(dir, "apply.cmd")
	body := "@echo off\r\n" +
		fmt.Sprintf("\"%s\" update-apply --staged \"%s\" --task %s --delay 8s%s\r\n",
			staged, staged, windowsUpdateTask, splitArg)
	if err := os.WriteFile(script, []byte(body), 0600); err != nil {
		return err
	}

	out, err := exec.Command("schtasks", windowsUpdateTaskArgs(windowsUpdateTask, script)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("create update task: %v: %s", err, strings.TrimSpace(string(out)))
	}
	out, err = exec.Command("schtasks", "/run", "/tn", windowsUpdateTask).CombinedOutput()
	if err != nil {
		return fmt.Errorf("run update task: %v: %s", err, strings.TrimSpace(string(out)))
	}
	fmt.Println("update staged; the scheduled task will apply it in a few seconds")
	return nil
}

// cmdUpdateApply is run by the scheduled task, after the updating process has
// exited so the installed executable is no longer locked. It backs up the
// current binary, installs the staged release with the existing config, and
// restores the backup if the install fails.
func cmdUpdateApply(args []string) error {
	fs := newFlagSet("update-apply")
	staged := fs.String("staged", "", "staged release binary")
	task := fs.String("task", "", "scheduled task to delete after applying")
	split := fs.Bool("split", false, "preserve split mode")
	delay := fs.Duration("delay", 8*time.Second, "wait for the updating process to exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		return errors.New("update-apply is Windows only")
	}
	if *staged == "" {
		return errors.New("missing --staged")
	}
	if err := newPlatform().RequirePrivilege(); err != nil {
		return err
	}
	if *delay > 0 {
		time.Sleep(*delay)
	}

	installed, err := installedExePath()
	if err != nil {
		return err
	}
	backup := installed + ".prev"
	if err := copyExecutable(installed, backup); err != nil {
		return fmt.Errorf("back up installed binary: %w", err)
	}

	installArgs := []string{"install", "--keep-config"}
	if *split {
		installArgs = append(installArgs, "--split")
	}
	cmd := exec.Command(*staged, installArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		_ = copyExecutable(backup, installed)
		_ = newPlatform().StartService()
		if *task != "" {
			_ = exec.Command("schtasks", "/delete", "/tn", *task, "/f").Run()
		}
		return fmt.Errorf("install failed, previous binary restored: %w", err)
	}
	if *task != "" {
		_ = exec.Command("schtasks", "/delete", "/tn", *task, "/f").Run()
	}
	fmt.Printf("update applied to %s\n", installed)
	return nil
}
