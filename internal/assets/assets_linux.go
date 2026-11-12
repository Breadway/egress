//go:build linux && delivery

package assets

import _ "embed"

//go:embed assets/wstunnel-linux-amd64
var Wstunnel []byte
