//go:build !windows && !linux && !darwin

package main

// Non-delivery platforms embed nothing. Linux, Windows and Darwin delivery
// builds embed their native wstunnel fallback executable.
var embeddedWstunnel []byte
var embeddedWireGuardMSI []byte
