//go:build windows

package egress

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"egress/internal/core"
)

// defenderTargets are the things Defender quarantines: the directory holding
// the installed binaries, and the two executables themselves.
func defenderTargets() (paths, procs []string) {
	dir := core.InstallDir()
	return []string{dir}, []string{
		filepath.Join(dir, "egress.exe"),
		filepath.Join(dir, "wstunnel.exe"),
	}
}

func defenderScript(remove bool) string {
	cmdlet := "Add-MpPreference"
	if remove {
		cmdlet = "Remove-MpPreference"
	}
	var b strings.Builder
	paths, procs := defenderTargets()
	for _, p := range paths {
		fmt.Fprintf(&b, "%s -ExclusionPath '%s'\n", cmdlet, p)
	}
	for _, p := range procs {
		fmt.Fprintf(&b, "%s -ExclusionProcess '%s'\n", cmdlet, p)
	}
	b.WriteString("(Get-MpPreference).ExclusionPath | Where-Object { $_ -like '*egress*' }")
	return b.String()
}

func runDefender(cmdletScript string) (string, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", cmdletScript).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("Defender preference change failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// cmdDefender adds or removes the antivirus exclusion. Windows has no other
// lever for a binary it refuses to run, so this is offered explicitly with the
// cost stated, never silently during install.
func cmdDefender(args []string) error {
	fs := newFlagSet("allow-defender")
	remove := fs.Bool("remove", false, "remove the exclusion instead of adding it")
	debug := fs.Bool("debug", false, "trace commands")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setupLogging(resolveDebug(*debug))
	if err := newPlatform().RequirePrivilege(); err != nil {
		return err
	}
	paths, _ := defenderTargets()
	if *remove {
		if _, err := runDefender(defenderScript(true)); err != nil {
			return err
		}
		fmt.Println("Defender exclusions removed")
		return nil
	}
	remaining, err := runDefender(defenderScript(false))
	if err != nil {
		return err
	}
	fmt.Printf("Defender now excludes %s\n", paths[0])
	if remaining != "" {
		fmt.Println("current egress exclusions:")
		fmt.Println(remaining)
	}
	fmt.Println("this lowers protection for that directory until the build is signed;")
	fmt.Println("`egress allow-defender --remove` or `egress remove` takes it back out")
	return nil
}

// cleanupDefenderExclusions runs from remove so a machine is not left with a
// standing exclusion for a directory that no longer exists. Best effort.
func cleanupDefenderExclusions() {
	_, _ = runDefender(defenderScript(true))
}
