package egress

import (
	platformpkg "egress/internal/platform"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
