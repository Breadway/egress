package platform

import (
	"bytes"
	"strings"
	"testing"
)

// TestShowPrintsCommandOutput is the regression that mattered: a support
// bundle carried command lines with no output, so every section looked empty
// and a broken install could not be told from a working one.
func TestShowPrintsCommandOutput(t *testing.T) {
	var b bytes.Buffer
	show(&b, "sh", "-c", "echo hello-from-the-machine")
	out := b.String()
	if !strings.Contains(out, "$ sh -c echo hello-from-the-machine") {
		t.Errorf("missing command line:\n%s", out)
	}
	if !strings.Contains(out, "hello-from-the-machine") {
		t.Errorf("missing command output:\n%s", out)
	}
}

// TestShowReportsFailure keeps a failing probe visible instead of silent.
func TestShowReportsFailure(t *testing.T) {
	var b bytes.Buffer
	show(&b, "sh", "-c", "exit 3")
	if !strings.Contains(b.String(), "exit status 3") {
		t.Errorf("missing failure note:\n%s", b.String())
	}
}
