//go:build linux && delivery

package egress

import _ "embed"

//go:embed assets/wstunnel-linux-amd64
var embeddedWstunnel []byte
