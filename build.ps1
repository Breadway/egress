# Build egress on Windows with a key compiled in.
#
# Equivalent to build.sh. Use this if you are building on the target machine
# instead of cross-compiling from Linux.
#
#   .\build.ps1 -Generate -IP 10.88.0.4
#   .\build.ps1 -KeyFile .\device4.key -IP 10.88.0.4
#
# The public key must be added to Aegis before the binary will handshake.

param(
    [string]$Key,
    [string]$KeyFile,
    [switch]$Generate,
    [string]$IP = "10.88.0.4",
    [ValidateSet("linux", "windows", "darwin")][string]$OS = "windows",
    [ValidateSet("amd64", "arm64")][string]$Arch = "amd64",
    [string]$Out,
    [string]$SaveKey,
    [switch]$DebugBuild
)

$ErrorActionPreference = "Stop"

function Fail($message) {
    Write-Host "error: $message" -ForegroundColor Red
    exit 1
}

if (-not (Get-Command go -ErrorAction SilentlyContinue)) { Fail "go is not on PATH" }

if ($Generate) {
    $bytes = New-Object 'byte[]' 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $Key = [Convert]::ToBase64String($bytes)
}
elseif ($KeyFile) {
    if (-not (Test-Path $KeyFile)) { Fail "cannot read $KeyFile" }
    $Key = (Get-Content -Raw $KeyFile).Trim()
}

if (-not $Key) { Fail "no key given; use -Key, -KeyFile or -Generate" }
if ($Key.Length -ne 44) { Fail "key must be 44 characters, got $($Key.Length)" }
if (-not $Key.EndsWith("=")) { Fail "key must end with '='" }
if ($Key -notmatch '^[A-Za-z0-9+/]+=$') { Fail "key is not valid base64" }

try { $decoded = [Convert]::FromBase64String($Key) } catch { Fail "key is not valid base64" }
if ($decoded.Length -ne 32) { Fail "key does not decode to 32 bytes" }

if ($IP -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { Fail "-IP is not a dotted IPv4 address" }
foreach ($part in $IP.Split(".")) {
    if ([int]$part -gt 255) { Fail "-IP is not a valid IPv4 address: $IP" }
}

if (-not $Out) {
    $Out = "dist\egress-$OS-$Arch"
    if ($OS -eq "windows") { $Out = "$Out.exe" }
}
$dir = Split-Path -Parent $Out
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }

# Delivery builds embed the fallback client (plus the WireGuard installer on
# Windows) so the target never needs GitHub or winget.
if ($OS -eq "windows") {
    $assets = @{
        "assets\wstunnel-windows-amd64.exe" = "c7b5b53c1476995310fe10b2f3f6d19006e5a5948984d8d25682b47e8ecb8f73"
        "assets\wireguard-amd64-1.1.1.msi"  = "7bfed60ad61b785c914b38b61555a975488e1d3ec472dbfb2fcdf498fca75242"
    }
    foreach ($path in $assets.Keys) {
        if (-not (Test-Path $path)) { Fail "missing $path; Windows builds embed it" }
        $hash = (Get-FileHash $path -Algorithm SHA256).Hash.ToLower()
        if ($hash -ne $assets[$path]) { Fail "$path checksum mismatch" }
    }
}
if ($OS -eq "linux") {
    $linuxAsset = "assets/wstunnel-linux-amd64"
    $linuxWant = "62b26d0ee0f2211cef15fa1b85173fe687bc6698121842bf324359b412afc151"
    if (-not (Test-Path $linuxAsset)) { Fail "missing $linuxAsset; Linux delivery builds embed it" }
    $hash = (Get-FileHash $linuxAsset -Algorithm SHA256).Hash.ToLower()
    if ($hash -ne $linuxWant) { Fail "$linuxAsset checksum mismatch" }
}
if ($OS -eq "darwin") {
    $darwinAsset = "assets/wstunnel-darwin-$Arch"
    $darwinWant = @{
        "amd64" = "72349e8eda9b80762e809b51dbe3c81aea8094b57da6ab6bb97274f048be4adb"
        "arm64" = "3c814a9b16481b6b17b9ea02b679b8b21454788da6c61366c4d26fca823c9feb"
    }[$Arch]
    if (-not $darwinWant) { Fail "unsupported arch for darwin: $Arch" }
    if (-not (Test-Path $darwinAsset)) { Fail "missing $darwinAsset; Darwin delivery builds embed it" }
    $hash = (Get-FileHash $darwinAsset -Algorithm SHA256).Hash.ToLower()
    if ($hash -ne $darwinWant) { Fail "$darwinAsset checksum mismatch" }
}

$env:GOOS = $OS
$env:GOARCH = $Arch
$env:CGO_ENABLED = "0"

Write-Host ""
Write-Host "private key: $Key"
Write-Host "public key:  (run $Out pubkey to display it)"
Write-Host "tunnel ip:   $IP/32"
Write-Host "building:    $OS/$Arch -> $Out"
Write-Host ""

$debugLdflag = ""
if ($DebugBuild) { $debugLdflag = " -X main.defaultDebug=true" }

& go build -tags delivery -trimpath -buildvcs=false `
    -ldflags "-s -w -X main.embeddedKey=$Key -X main.embeddedClientIP=$IP -X main.buildVersion=$(Get-Date -Format 'yyyyMMdd')$debugLdflag" `
    -o $Out .
if ($LASTEXITCODE -ne 0) { Fail "go build failed" }

# The key is a plain string in the binary, so it must be findable there.
$raw = [System.IO.File]::ReadAllText((Resolve-Path $Out), [System.Text.Encoding]::Latin1)
if (-not $raw.Contains($Key)) {
    Fail "the key is not in the output binary; check the -X variable names"
}

if ($SaveKey) {
    Set-Content -Path $SaveKey -Value $Key -NoNewline
    Write-Host "saved key:   $SaveKey"
}

Write-Host @"

Next steps
  1. Add the public key to Aegis with allowed-ips $IP/32, and to
     /etc/wireguard/wg0.conf so it survives a restart.
  2. Copy only $Out to the target machine and run it as Administrator.
  3. Confirm the exit with:  egress verify

Warning
  The private key is recoverable from the binary. Treat the file as a
  credential, and rebuild plus remove the Aegis peer if it leaks.
"@
