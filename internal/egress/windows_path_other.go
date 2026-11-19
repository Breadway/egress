//go:build !windows

package egress

// PATH registration is a Windows convenience only: elsewhere the binary is
// installed at a path the user already controls.
func configureWindowsPath(string) {}

func cleanupWindowsPath() {}
