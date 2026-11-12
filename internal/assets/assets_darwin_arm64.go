//go:build darwin && arm64 && delivery

package assets

import _ "embed"

//go:embed assets/wstunnel-darwin-arm64
var Wstunnel []byte
