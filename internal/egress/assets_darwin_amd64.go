//go:build darwin && amd64 && delivery

package egress

import _ "embed"

//go:embed assets/wstunnel-darwin-amd64
var embeddedWstunnel []byte
