//go:build darwin && arm64 && delivery

package main

import _ "embed"

//go:embed assets/wstunnel-darwin-arm64
var embeddedWstunnel []byte
