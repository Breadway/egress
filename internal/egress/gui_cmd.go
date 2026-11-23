package egress

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// cmdGUI opens the desktop app. The Tauri binary stays a separate build (it
// carries the webview); this command finds it, launches it detached, and gets
// out of the way. A second launch is folded into the running app by the
// single-instance plugin.
func cmdGUI(args []string) error {
	fs := newFlagSet("gui")
	wait := fs.Bool("wait", false, "wait for the app to exit")
	tray := fs.Bool("tray", false, "start hidden in the tray")
	if err := fs.Parse(args); err != nil {
		return err
	}
	guiArgs := []string{}
	if *tray {
		guiArgs = append(guiArgs, "--tray")
	}
	return launchGUI(*wait, guiArgs...)
}

func launchGUI(wait bool, guiArgs ...string) error {
	path, err := guiBinary()
	if err != nil {
		return err
	}
	cmd := exec.Command(path, guiArgs...)
	if wait {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := configureGUICommand(cmd); err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", path, err)
	}
	if wait {
		return cmd.Wait()
	}
	return cmd.Process.Release()
}

// guiBinary resolves the desktop app. EGRESS_GUI wins for development, then a
// sibling of the egress binary (how a single install lays it out), then PATH.
func guiBinary() (string, error) {
	if path := os.Getenv("EGRESS_GUI"); path != "" {
		if err := executableFile(path); err == nil {
			return path, nil
		}
	}
	name := "egress-gui"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), name)
		if err := executableFile(candidate); err == nil {
			return candidate, nil
		}
	}
	if runtime.GOOS == "windows" {
		if base := os.Getenv("LOCALAPPDATA"); base != "" {
			candidate := filepath.Join(base, "egress-gui", name)
			if err := executableFile(candidate); err == nil {
				return candidate, nil
			}
		}
	}
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}
	return "", errors.New("egress-gui is not installed; run `bakery install egress-gui` on Linux, or put egress-gui.exe next to egress.exe, in %LOCALAPPDATA%\\egress-gui, or on PATH on Windows")
}

func executableFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	if runtime.GOOS != "windows" && info.Mode()&0111 == 0 {
		return fmt.Errorf("%s is not executable", path)
	}
	return nil
}
