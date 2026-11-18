//go:build !windows

package platform

// Directory ACL hardening is a Windows concern; elsewhere the install path is
// owned by the user or root as usual.
func ensureBinaryACL(string) {}
