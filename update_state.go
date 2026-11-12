package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

// updateState records which signed release this install has applied. Without
// it, a republished build with the same version and a force flag would be
// reinstalled on every check.
type updateState struct {
	ManifestSHA string `json:"manifest_sha"`
}

func updateStatePath() string {
	switch runtime.GOOS {
	case "windows":
		return `C:\ProgramData\egress\update-state.json`
	case "linux":
		return "/var/lib/egress/update-state.json"
	default:
		if dir, err := os.UserConfigDir(); err == nil {
			return filepath.Join(dir, "egress", "update-state.json")
		}
		return "update-state.json"
	}
}

func appliedRelease() (string, error) {
	var st updateState
	data, err := os.ReadFile(updateStatePath())
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return "", err
	}
	return st.ManifestSHA, nil
}

func recordAppliedRelease(sha string) error {
	path := updateStatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(updateState{ManifestSHA: sha})
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
