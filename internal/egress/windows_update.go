package egress

import (
	"context"
	platformpkg "egress/internal/platform"
	"egress/internal/winlog"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const windowsUpdateTask = "egress-update-apply"

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

// cmdUpdateApply is run by the scheduled task, after the updating process has
// exited so the installed executable is no longer locked. It backs up the
// current binary, installs the staged release with the existing config,
// restores the backup if the install fails, and records which release
// actually took effect.
func cmdUpdateApply(args []string) error {
	fs := newFlagSet("update-apply")
	staged := fs.String("staged", "", "staged release binary")
	task := fs.String("task", "", "scheduled task to delete after applying")
	sha := fs.String("sha", "", "release sha256, recorded so a stuck update backs off")
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

	// Whichever path this returns on, never leave the service stopped: the
	// install below stops it, and a crash or a refused swap used to leave the
	// machine with no resolver until someone noticed.
	defer func() {
		if !newPlatform().ServiceActive() {
			if err := newPlatform().StartService(); err != nil {
				winlog.Notify("error", "update left the service stopped: "+err.Error())
			}
		}
	}()

	installed, err := installedExePath()
	if err != nil {
		return err
	}
	backup := installed + ".prev"
	if err := copyExecutable(installed, backup); err != nil {
		// A blocked or unreadable installed binary must not wedge updates:
		// the staged release is already verified, and install replaces the
		// file anyway. Keep any existing backup, which is a known-good build.
		debugf("could not back up the installed binary: %v", err)
	}

	installArgs := []string{"install", "--keep-config"}
	if *split {
		// Split mode on Windows is the proxy/PAC path and has no wg0.conf to
		// reuse.
		installArgs = []string{"install", "--split"}
	}
	cmd := exec.Command(*staged, installArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// The failed install may have left the new service running from the
		// new image. Stop it before putting the old one back: a running image
		// cannot be replaced.
		_ = newPlatform().StopService()
		if rerr := platformpkg.ReplaceFile(backup, installed); rerr != nil {
			fmt.Fprintf(os.Stderr, "could not restore the previous binary: %v\n", rerr)
		}
		_ = newPlatform().StartService()
		winlog.Notify("error", "update apply failed, previous binary restored: "+err.Error())
		if *sha != "" {
			if rerr := recordFailedRelease(*sha); rerr != nil {
				debugf("could not record the failed release: %v", rerr)
			}
		}
		if *task != "" {
			_ = exec.Command("schtasks", "/delete", "/tn", *task, "/f").Run()
		}
		return fmt.Errorf("install failed, previous binary restored: %w", err)
	}
	// Fail open: a swap that leaves an image Windows refuses to load is worse
	// than a failed update. Prove the new binary runs before recording success
	// and before the previous one stops being the way back.
	if verr := runInstalled(installed); verr != nil {
		winlog.Notify("error", "updated binary does not run, restoring the previous build: "+verr.Error())
		_ = newPlatform().StopService()
		if rerr := forceRestore(backup, installed); rerr != nil {
			winlog.Notify("error", "previous binary could not be restored: "+rerr.Error())
			if *sha != "" {
				_ = recordFailedRelease(*sha)
			}
			if *task != "" {
				_ = exec.Command("schtasks", "/delete", "/tn", *task, "/f").Run()
			}
			return fmt.Errorf("updated binary does not run (%v) and the previous one could not be restored: %w", verr, rerr)
		}
		_ = newPlatform().StartService()
		if *sha != "" {
			_ = recordFailedRelease(*sha)
		}
		if *task != "" {
			_ = exec.Command("schtasks", "/delete", "/tn", *task, "/f").Run()
		}
		return fmt.Errorf("updated binary did not run, previous build restored: %w", verr)
	}
	if *sha != "" {
		if err := recordAppliedRelease(*sha); err != nil {
			debugf("could not record the applied release: %v", err)
		}
	}
	if *task != "" {
		_ = exec.Command("schtasks", "/delete", "/tn", *task, "/f").Run()
	}
	fmt.Printf("update applied to %s\n", installed)
	return nil
}

// runInstalled proves a binary at path actually executes. A file can land on
// disk with the right bytes and still be refused by Windows, which is the one
// failure an update must never leave behind.
func runInstalled(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "version").CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return fmt.Errorf("%v (%s)", err, msg)
	}
	return nil
}

// forceRestore puts the backup back even when the file it replaces has been
// locked down to the point that a plain rename fails. It clears the ACL first,
// which is the state Defender leaves a quarantined file in.
func forceRestore(backup, installed string) error {
	if _, err := os.Stat(backup); err != nil {
		return fmt.Errorf("no backup to restore from: %w", err)
	}
	_ = exec.Command("takeown", "/f", installed).Run()
	_ = exec.Command("icacls", installed, "/reset").Run()
	if err := platformpkg.ReplaceFile(backup, installed); err != nil {
		return err
	}
	return runInstalled(installed)
}
