//go:build darwin && amd64 && delivery

package assets

import _ "embed"

//go:embed assets/wstunnel-darwin-amd64
var Wstunnel []byte
