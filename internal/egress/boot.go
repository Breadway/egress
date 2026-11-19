package egress

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"egress/internal/split"
)

// bootMarkerPath records "do not start at boot" across installs and updates.
// An update reinstalls the service, so the preference has to live outside it.
func bootMarkerPath() string { return filepath.Join(split.ProfileDir(), "no-boot") }

// bootDisabled reports the saved preference.
func bootDisabled() bool {
	_, err := os.Stat(bootMarkerPath())
	return err == nil
}

func setBootPreference(off bool) error {
	path := bootMarkerPath()
	if off {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("1\n"), 0600)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// cmdBoot turns the boot start on or off without touching the current session.
// The update check keeps running either way, so a machine that stays off the
// tunnel still receives fixes.
func cmdBoot(args []string) error {
	if len(args) != 1 || (args[0] != "on" && args[0] != "off") {
		return errors.New("usage: egress boot on|off")
	}
	off := args[0] == "off"
	plat := newPlatform()
	if err := plat.RequirePrivilege(); err != nil {
		return err
	}
	if err := setBootPreference(off); err != nil {
		return err
	}
	if err := setBootStart(!off); err != nil {
		return err
	}
	if off {
		fmt.Println("egress will not start at boot; the current session is unchanged")
	} else {
		fmt.Println("egress will start at boot again")
	}
	return nil
}

// cmdNetworks manages the SSID allowlist used by the per-user proxy.
func cmdNetworks(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: egress networks list|add <ssid>|remove <ssid>|clear")
	}
	dir := split.ProfileDir()
	if runtime.GOOS != "windows" {
		fmt.Fprintln(os.Stderr, "note: the SSID allowlist is enforced by the Windows per-user proxy; on this platform it is recorded but not applied")
	}
	switch args[0] {
	case "list":
		ssids := split.LoadNetworks(dir)
		if len(ssids) == 0 {
			fmt.Println("any network (no allowlist)")
			return nil
		}
		for _, ssid := range ssids {
			fmt.Println(ssid)
		}
		return nil
	case "add":
		if len(args) < 2 {
			return errors.New("usage: egress networks add <ssid>...")
		}
		ssids := split.LoadNetworks(dir)
		for _, add := range args[1:] {
			found := false
			for _, have := range ssids {
				if have == add {
					found = true
				}
			}
			if !found {
				ssids = append(ssids, add)
			}
		}
		if err := split.SaveNetworks(dir, ssids); err != nil {
			return err
		}
		fmt.Printf("networks: %v\n", ssids)
		return nil
	case "remove":
		if len(args) < 2 {
			return errors.New("usage: egress networks remove <ssid>")
		}
		var keep []string
		for _, have := range split.LoadNetworks(dir) {
			drop := false
			for _, name := range args[1:] {
				if have == name {
					drop = true
				}
			}
			if !drop {
				keep = append(keep, have)
			}
		}
		if err := split.SaveNetworks(dir, keep); err != nil {
			return err
		}
		fmt.Printf("networks: %v\n", keep)
		return nil
	case "clear":
		if err := split.SaveNetworks(dir, nil); err != nil {
			return err
		}
		fmt.Println("any network")
		return nil
	}
	return fmt.Errorf("unknown networks action %q", args[0])
}
