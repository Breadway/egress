package egress

import (
	"os"
	"path/filepath"
	"strings"

	"egress/internal/core"
)

// exit-choice pins one registered exit by id. An empty file means the first
// exit in the feed, which is the historical behaviour.
func exitChoicePath() string {
	return filepath.Join(core.StateDir(), "exit-choice")
}

func loadExitChoice() string {
	data, err := os.ReadFile(exitChoicePath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func storeExitChoice(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		if err := os.Remove(exitChoicePath()); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(core.StateDir(), 0700); err != nil {
		return err
	}
	return os.WriteFile(exitChoicePath(), []byte(id+"\n"), 0644)
}
