//go:build windows

package platform

// PowerShell runs a PowerShell command and returns its trimmed output.
func PowerShell(script string) (string, error) { return powershell(script) }
