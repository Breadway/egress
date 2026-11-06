//go:build linux

package main

import _ "embed"

//go:embed assets/wstunnel-linux-amd64
var embeddedWstunnel []byte
