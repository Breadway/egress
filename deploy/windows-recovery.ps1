#requires -RunAsAdministrator
<#
.SYNOPSIS
  Undo an egress install when egress.exe cannot run.

.DESCRIPTION
  Mirrors what "egress.exe remove" does: stop and delete the scheduled tasks,
  stop and delete the WireGuard tunnel services, clear the PAC and WinHTTP
  proxy, put adapter DNS back on DHCP, drop the pinned routes and flush the
  resolver cache.

  Use it when the binary is missing, blocked by antivirus or was deleted by
  hand. Nothing here needs egress.exe, so a half-removed install that left DNS
  pointing at a dead 127.0.0.1 listener can be repaired.

  Windows keeps adapter DNS at 127.0.0.1 after an install, so once the
  resolver process is gone every lookup fails. That is the symptom this fixes.

.NOTES
  Leaves C:\ProgramData\egress in place unless -PurgeFiles is given, because a
  delete cannot always succeed while an image is still running. Run -PurgeFiles
  after a reboot for a clean directory.
#>
param(
    [switch]$PurgeFiles
)

$ErrorActionPreference = 'Continue'
$installDir = 'C:\ProgramData\egress'

function Step($text) { Write-Host "  $text" }

Write-Host 'egress recovery'

Step 'stopping and deleting the scheduled tasks'
foreach ($task in 'egress', 'egress-update-check', 'egress-update-apply', 'egress-split-user') {
    schtasks /end /tn $task 2>$null | Out-Null
    schtasks /delete /tn $task /f 2>$null | Out-Null
}

Step 'stopping leftover processes'
Get-CimInstance Win32_Process -Filter "Name='egress.exe' OR Name='wstunnel.exe'" -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

Step 'stopping and deleting the tunnel services'
foreach ($service in 'WireGuardTunnel$wg0', 'WireGuardTunnel$wg0ws', 'WireGuardTunnel$wgexit') {
    sc.exe stop $service 2>$null | Out-Null
    sc.exe delete $service 2>$null | Out-Null
}

Step 'clearing the proxy and PAC layers'
netsh winhttp reset proxy 2>$null | Out-Null
$inet = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
Remove-ItemProperty -Path $inet -Name AutoConfigURL -ErrorAction SilentlyContinue
Set-ItemProperty -Path $inet -Name ProxyEnable -Value 0 -Type DWord -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name egress -ErrorAction SilentlyContinue

Step 'removing the PATH entry'
$envKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
$cur = [string](Get-ItemProperty -Path $envKey -Name Path -ErrorAction SilentlyContinue).Path
if ($cur) {
    $kept = @($cur -split ';' | Where-Object { $_ -ne '' -and $_.TrimEnd('\') -ne $installDir.TrimEnd('\') })
    if ($kept.Count -gt 0 -and ($kept -join ';') -ne $cur) {
        Set-ItemProperty -Path $envKey -Name Path -Value ($kept -join ';') -Type ExpandString
    }
}

Step 'putting adapter DNS back on DHCP'
Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.Status -eq 'Up' } |
    ForEach-Object {
        Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue
    }

Step 'dropping the pinned routes'
route delete 10.88.0.1 2>$null | Out-Null
route delete 152.69.174.7 2>$null | Out-Null

Step 'flushing the resolver cache'
Clear-DnsClientCache -ErrorAction SilentlyContinue
ipconfig /flushdns 2>$null | Out-Null

if ($PurgeFiles) {
    Step "deleting $installDir"
    Remove-Item -LiteralPath $installDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host 'DNS servers now:'
Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Format-Table InterfaceAlias, ServerAddresses -AutoSize

Write-Host 'Resolution check:'
try {
    Resolve-DnsName example.com -ErrorAction Stop |
        Select-Object -First 2 Name, Type, IPAddress |
        Format-Table -AutoSize
} catch {
    Write-Host "  still failing: $($_.Exception.Message)"
    Write-Host '  run: ipconfig /renew, then check the adapter DNS above is not 127.0.0.1'
}
