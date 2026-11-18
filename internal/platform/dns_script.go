package platform

import "fmt"

// applyDNSScript builds the PowerShell that points an adapter at the local
// resolver.
//
// It sets the listener first and a server Windows was already using second, so
// a dead or uninstalled listener degrades to plain DNS instead of taking every
// lookup down with it. The previous server list is remembered in dir because
// the next call sees an adapter that only carries 127.0.0.1, and the DHCP
// server would otherwise be lost on the second apply.
//
// Pure so the exact script stays testable off Windows.
func applyDNSScript(iface, dir string) string {
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$iface = %s
$dir = '%s'
$fallback = Join-Path $dir 'dns-fallback.txt'
$current = @(Get-DnsClientServerAddress -InterfaceIndex $iface -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
$dhcp = @($current | Where-Object { $_ -and $_ -ne '127.0.0.1' })
if ($dhcp.Count -gt 0) {
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $dhcp | Set-Content -Path $fallback
} elseif (Test-Path $fallback) {
  $dhcp = @(Get-Content $fallback | Where-Object { $_ })
}
$servers = @('127.0.0.1') + @($dhcp | Select-Object -First 1)
Set-DnsClientServerAddress -InterfaceIndex $iface -ServerAddress $servers`, iface, dir)
}
