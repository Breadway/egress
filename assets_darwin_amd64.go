//go:build darwin && amd64 && delivery

package main

import _ "embed"

//go:embed assets/wstunnel-darwin-amd64
var embeddedWstunnel []byte
