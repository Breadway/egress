package supervisor

import (
	"testing"
	"time"
)

func TestDoHRecoveryStep(t *testing.T) {
	base := time.Date(2026, 11, 12, 13, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		now      time.Time
		since    time.Time
		recovery time.Time
		want     dohAction
	}{
		{
			name:  "first wedge resets",
			now:   base.Add(10 * time.Second),
			since: base,
			want:  dohReset,
		},
		{
			name:     "recent reset waits",
			now:      base.Add(30 * time.Second),
			since:    base,
			recovery: base.Add(10 * time.Second),
			want:     dohWait,
		},
		{
			name:     "reset interval elapsed",
			now:      base.Add(70 * time.Second),
			since:    base,
			recovery: base.Add(10 * time.Second),
			want:     dohReset,
		},
		{
			name:     "gives up after the window even if resetting",
			now:      base.Add(5 * time.Minute),
			since:    base,
			recovery: base.Add(4*time.Minute + 50*time.Second),
			want:     dohGiveUp,
		},
	}
	for _, tc := range cases {
		if got := dohRecoveryStep(tc.now, tc.since, tc.recovery); got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, got, tc.want)
		}
	}
}
