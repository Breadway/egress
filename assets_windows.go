//go:build windows

package main

import _ "embed"

// These vendor-approved, pinned artifacts are embedded into Windows delivery
// builds. The target therefore needs no access to winget, GitHub, or any other
// downloader before it can establish the WebSocket fallback.

//go:embed assets/wstunnel-windows-amd64.exe
var embeddedWstunnel []byte

//go:embed assets/wireguard-amd64-1.1.1.msi
var embeddedWireGuardMSI []byte
