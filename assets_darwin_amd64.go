//go:build darwin && amd64

package main

import _ "embed"

//go:embed assets/wstunnel-darwin-amd64
var embeddedWstunnel []byte

// SHA-256 of the pinned wstunnel 11.1.0 darwin/amd64 binary.
const wstunnelDarwinSHA256 = "72349e8eda9b80762e809b51dbe3c81aea8094b57da6ab6bb97274f048be4adb"
