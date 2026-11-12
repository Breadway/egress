package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

// deviceIdentity is the non-secret half of a device's tunnel identity, kept on
// disk so split installs and generic updates can identify themselves in install
// reports without holding a private key.
type deviceIdentity struct {
	Pubkey string `json:"pubkey"`
	IP     string `json:"ip,omitempty"`
}

func deviceIdentityPath() string {
	switch runtime.GOOS {
	case "windows":
		return `C:\ProgramData\egress\device.json`
	case "linux":
		return "/var/lib/egress/device.json"
	default:
		if dir, err := os.UserConfigDir(); err == nil {
			return filepath.Join(dir, "egress", "device.json")
		}
		return "device.json"
	}
}

func loadDeviceIdentity() (deviceIdentity, error) {
	var id deviceIdentity
	data, err := os.ReadFile(deviceIdentityPath())
	if err != nil {
		return id, err
	}
	if err := json.Unmarshal(data, &id); err != nil {
		return id, err
	}
	return id, nil
}

func saveDeviceIdentity(id deviceIdentity) error {
	path := deviceIdentityPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
