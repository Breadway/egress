package platform

import (
	"strings"
	"testing"
)

// TestApplyDNSScriptKeepsFallback pins the fail-over ordering: the local
// resolver first, a server Windows already had second, and a remembered list
// so the second apply on an already-rewritten adapter does not lose it.
func TestApplyDNSScriptKeepsFallback(t *testing.T) {
	got := applyDNSScript("12", `C:\ProgramData\egress`)

	for _, want := range []string{
		"$iface = 12",
		`$dir = 'C:\ProgramData\egress'`,
		"dns-fallback.txt",
		"$dhcp | Set-Content -Path $fallback",
		"Get-Content $fallback",
		"@('127.0.0.1') + @($dhcp | Select-Object -First 1)",
		"Set-DnsClientServerAddress -InterfaceIndex $iface -ServerAddress $servers",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("script missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "-ServerAddress '127.0.0.1'") {
		t.Error("script still sets the listener as the only server")
	}
}
