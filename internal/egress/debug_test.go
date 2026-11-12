package egress

import "testing"

// TestResolveDebug covers the --debug flag OR build-time default matrix.
// The linker-set path (defaultDebug == "true") is exercised by swapping the
// package var, the same mechanism -X uses.
func TestResolveDebug(t *testing.T) {
	old := defaultDebug
	defer func() { defaultDebug = old }()

	defaultDebug = "false"
	if resolveDebug(true) != true {
		t.Error("explicit --debug must win when default is off")
	}
	if resolveDebug(false) != false {
		t.Error("quiet build without --debug must stay quiet")
	}

	defaultDebug = "true"
	if resolveDebug(false) != true {
		t.Error("debug-default build without --debug must log")
	}
	if resolveDebug(true) != true {
		t.Error("debug-default build with --debug must log")
	}

	defaultDebug = "yes"
	if resolveDebug(false) != false {
		t.Error("only the exact string \"true\" enables the default")
	}
}
