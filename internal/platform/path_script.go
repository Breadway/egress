package platform

import "fmt"

// machinePathScript builds the PowerShell that adds or removes one directory
// on the machine PATH.
//
// The value is edited in place: the registry entry is read as a string, the
// entries keep their order, and it is written back as an expandable string so
// entries like %SystemRoot% keep working. The broadcast at the end is what
// makes Explorer hand the new value to shells started afterwards; without it
// the change only shows up after a sign-out.
func machinePathScript(dir string, add bool) string {
	change := `$new = @($dir) + @($parts | Where-Object { $_.TrimEnd('\') -ne $dir.TrimEnd('\') })
$new = @($new | Select-Object -Unique)`
	if !add {
		change = `$new = @($parts | Where-Object { $_.TrimEnd('\') -ne $dir.TrimEnd('\') })
if ($new.Count -eq 0) { throw 'refusing to empty the machine PATH' }`
	}
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$dir = '%s'
$key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
$cur = [string](Get-ItemProperty -Path $key -Name Path -ErrorAction Stop).Path
$parts = @($cur -split ';' | Where-Object { $_ -ne '' })
%s
Set-ItemProperty -Path $key -Name Path -Value ($new -join ';') -Type ExpandString
$env:Path = ($new -join ';')

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class EgressPathBroadcast {
  [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
  public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
}
"@
Add-Type -TypeDefinition $sig -ErrorAction SilentlyContinue
$res = [UIntPtr]::Zero
[void][EgressPathBroadcast]::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$res)`, dir, change)
}
