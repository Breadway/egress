package platform

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"egress/internal/core"
	"egress/internal/logx"
)

// InstalledBinaryPath is the canonical name under the install directory. The
// boot service and the scheduled task always reference it.
func InstalledBinaryPath() string {
	name := "egress"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(core.InstallDir(), name)
}

// EnsureInstalledBinary copies the running executable to the canonical path
// when it was started from anywhere else (Downloads, USB stick, /tmp) and
// returns that path, so an install survives a reboot and the service points at
// something stable.
func EnsureInstalledBinary() (string, error) {
	dest := InstalledBinaryPath()
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, rerr := filepath.EvalSymlinks(self); rerr == nil {
		self = resolved
	}
	if filepath.Clean(self) == filepath.Clean(dest) {
		return dest, nil
	}
	if a, errA := os.Stat(self); errA == nil {
		if b, errB := os.Stat(dest); errB == nil && os.SameFile(a, b) {
			return dest, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		return "", err
	}
	src, err := os.Open(self)
	if err != nil {
		return "", fmt.Errorf("read the running binary: %w", err)
	}
	defer src.Close()
	tmp := dest + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
	if err != nil {
		return "", err
	}
	_, copyErr := io.Copy(out, src)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("copy to %s: %w", dest, copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return "", closeErr
	}
	// Windows refuses to replace an image that is still mapped; the old
	// supervisor was stopped earlier, but its process may need a moment.
	var renameErr error
	for attempt := 0; attempt < 20; attempt++ {
		if renameErr = os.Rename(tmp, dest); renameErr == nil {
			logx.Debugf("installed binary to %s", dest)
			return dest, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = os.Remove(tmp)
	return "", fmt.Errorf("replace %s: %w", dest, renameErr)
}

// RemoveInstalledBinary deletes the canonical path unless that is the running
// executable, which cannot be unlinked on Windows and should not vanish
// underneath the user on Linux.
func RemoveInstalledBinary() {
	dest := InstalledBinaryPath()
	self, err := os.Executable()
	if err == nil {
		if resolved, rerr := filepath.EvalSymlinks(self); rerr == nil {
			self = resolved
		}
		if filepath.Clean(self) == filepath.Clean(dest) {
			fmt.Printf("the running binary is %s; delete it after this command exits\n", dest)
			return
		}
		if a, errA := os.Stat(self); errA == nil {
			if b, errB := os.Stat(dest); errB == nil && os.SameFile(a, b) {
				fmt.Printf("the running binary is %s; delete it after this command exits\n", dest)
				return
			}
		}
	}
	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
		fmt.Printf("could not delete %s: %v\n", dest, err)
	}
}
