//go:build windows

package egress

import "syscall"

const (
	// PROCESS_QUERY_LIMITED_INFORMATION opens a handle to processes in other
	// sessions, including SYSTEM, without the full access that
	// PROCESS_QUERY_INFORMATION needs. Go's os.FindProcess asks for the
	// latter, which an elevated administrator cannot get on a SYSTEM process.
	processQueryLimitedInformation = 0x1000
	stillActive                    = 259
)

// pidAlive reports whether pid is running, using a handle that does not
// require debug privilege.
func pidAlive(pid int) bool {
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == stillActive
}
