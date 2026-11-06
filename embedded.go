package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// extractEmbedded atomically writes an embedded dependency only after checking
// its pinned digest. Existing correct copies are reused.
func extractEmbedded(dest string, data []byte, want string) error {
	if len(data) == 0 {
		return fmt.Errorf("this build does not contain the required embedded dependency for %s", filepath.Base(dest))
	}
	if existing, err := os.ReadFile(dest); err == nil && digestMatches(existing, want) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		return err
	}
	if !digestMatches(data, want) {
		return fmt.Errorf("embedded dependency checksum mismatch for %s", filepath.Base(dest))
	}
	tmp := dest + ".new"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	var renameErr error
	for attempt := 0; attempt < 20; attempt++ {
		if renameErr = os.Rename(tmp, dest); renameErr == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = os.Remove(tmp)
	return renameErr
}

func digestMatches(data []byte, want string) bool {
	got := sha256.Sum256(data)
	return strings.EqualFold(hex.EncodeToString(got[:]), want)
}
