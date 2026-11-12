//go:build !delivery || (!windows && !linux && !darwin)

package assets

// Non-delivery builds embed nothing on any platform, so a clean checkout
// compiles and tests without the gitignored vendor binaries. Delivery
// builds (build.sh/build.ps1, -tags delivery) embed them per platform
// above; other delivery platforms embed nothing.
var Wstunnel []byte
var WireGuardMSI []byte
