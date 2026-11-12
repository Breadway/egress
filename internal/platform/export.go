package platform

// LogPath is where the debug log lives for this platform.
func LogPath() string { return logPath() }

// SpoolDir is the shared directory for the readiness marker and the pending
// report spool. It is not TempDir on Windows, where that is per-user.
func SpoolDir() string { return spoolDir() }
