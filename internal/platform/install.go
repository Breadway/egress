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

// removeStaleImages deletes images left aside by an earlier replacement. A
// file still mapped by the tray is skipped silently and retried next time.
func removeStaleImages(dest string) {
	matches, err := filepath.Glob(dest + ".old*")
	if err != nil {
		return
	}
	for _, path := range matches {
		_ = os.Remove(path)
	}
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
	// A previous install may have left the old image aside because a per-user
	// process still had it mapped. Remove whatever is no longer locked.
	removeStaleImages(dest)
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
	// Windows refuses to replace an image that is still mapped. The service
	// is stopped later in the install, and the per-user tray and proxy run
	// from this same file, so a plain rename of the destination is not
	// enough: move the old image aside first. Retry because the previous
	// process may still be exiting.
	var renameErr error
	for attempt := 0; attempt < 40; attempt++ {
		if renameErr = ReplaceFile(tmp, dest); renameErr == nil {
			logx.Debugf("installed binary to %s", dest)
			// A file created while the directory ACL was being rewritten can
			// inherit an empty DACL. Repair it here rather than leaving a
			// binary only its owner can load.
			ensureBinaryACL(dest)
			return dest, nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	_ = os.Remove(tmp)
	return "", fmt.Errorf("replace %s: %w", dest, renameErr)
}

// ReplaceFile moves src onto dst, coping with a dst that is a running image.
// Windows allows a running executable to be renamed but not replaced, so when
// the direct rename fails the old file is moved aside and the rename retried.
// The aside file is deleted when possible and again on the next install.
func ReplaceFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	old := dst + ".old"
	if err := os.Remove(old); err != nil && !os.IsNotExist(err) {
		old = fmt.Sprintf("%s.%d", dst, time.Now().UnixNano())
	}
	if err := os.Rename(dst, old); err != nil {
		if os.IsNotExist(err) {
			return os.Rename(src, dst)
		}
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		_ = os.Rename(old, dst)
		return err
	}
	_ = os.Remove(old)
	return nil
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
