//go:build darwin && arm64

package main

import _ "embed"

//go:embed assets/wstunnel-darwin-arm64
var embeddedWstunnel []byte

// SHA-256 of the pinned wstunnel 11.1.0 darwin/arm64 binary.
const wstunnelDarwinSHA256 = "3c814a9b16481b6b17b9ea02b679b8b21454788da6c61366c4d26fca823c9feb"
