//go:build !windows

package winlog

// The Windows event log is the place a technician looks when a user only has a
// screenshot. Other platforms already write to the journal or syslog.
func EnsureSource() {}

func Notify(string, string) {}
