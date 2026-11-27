package health

import (
	"errors"
	"strings"
	"testing"
)

func TestDescribeBrowserPathIsSilentOutsideWindowsSplit(t *testing.T) {
	r := Results{Tunnel: "up", Split: "ok"}
	got := DescribeBrowserPath(r, false, true, nil)
	if got.Browser != "" {
		t.Fatalf("browser = %q, want empty when not applicable", got.Browser)
	}
}

func TestDescribeBrowserPathRecordsSuccess(t *testing.T) {
	got := DescribeBrowserPath(Results{}, true, true, nil)
	if got.Browser != "ok" {
		t.Fatalf("browser = %q, want ok", got.Browser)
	}
}

func TestDescribeBrowserPathMarksAnUnrunSetup(t *testing.T) {
	got := DescribeBrowserPath(Results{Tunnel: "up", Split: "ok"}, true, false, nil)
	if got.Browser != BrowserNotConfigured {
		t.Fatalf("browser = %q, want the not-configured verdict", got.Browser)
	}
	if !strings.Contains(got.Browser, "egress enable") {
		t.Errorf("browser verdict %q does not name the recovery", got.Browser)
	}
	// The relay tunnel verdict must not keep reading ok once the browser half
	// is known to be missing.
	if got.Split == "ok" {
		t.Errorf("split = %q, want a verdict that does not call the split client ok", got.Split)
	}
	if !strings.Contains(got.Split, "browser path is not configured") {
		t.Errorf("split = %q, want it to name the unconfigured browser path", got.Split)
	}
}

func TestDescribeBrowserPathKeepsTheSetupError(t *testing.T) {
	got := DescribeBrowserPath(Results{}, true, false, errors.New("start the tray: access denied"))
	if !strings.Contains(got.Browser, "access denied") {
		t.Fatalf("browser = %q, want the setup error", got.Browser)
	}
	if !strings.Contains(got.Browser, "egress enable") {
		t.Errorf("browser verdict %q does not name the recovery", got.Browser)
	}
}

func TestGradeFailsAnUnconfiguredBrowserPath(t *testing.T) {
	healthyTunnel := Results{Tunnel: "up", Probe: "ok", Exit: "split", Split: "ok"}
	if got := healthyTunnel.Grade(); got != "functional" {
		t.Fatalf("grade without a browser verdict = %q, want functional", got)
	}

	parked := healthyTunnel
	parked.Browser = BrowserNotConfigured
	if got := parked.Grade(); got != "failed" {
		t.Fatalf("grade with an unconfigured browser = %q, want failed", got)
	}

	configured := healthyTunnel
	configured.Browser = "ok"
	if got := configured.Grade(); got != "functional" {
		t.Fatalf("grade with a configured browser = %q, want functional", got)
	}
}
