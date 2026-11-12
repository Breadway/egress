//go:build linux

package egress

import (
	"strings"
	"testing"
	"time"
)

func TestUpdateTimerUnits(t *testing.T) {
	daily := updateTimerUnit(0)
	if !strings.Contains(daily, "OnCalendar=daily") {
		t.Errorf("daily timer missing schedule:\n%s", daily)
	}
	parked := updateTimerUnit(30 * time.Minute)
	if !strings.Contains(parked, "OnUnitActiveSec=30m") {
		t.Errorf("parked timer missing interval:\n%s", parked)
	}
	if strings.Contains(parked, "OnCalendar") {
		t.Errorf("parked timer still daily:\n%s", parked)
	}
}
