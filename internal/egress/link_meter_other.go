//go:build !linux

package egress

// linkMeter has no portable counter source outside Linux yet. The app shows
// zero rather than inventing a number.
type linkMeter struct{}

func newLinkMeter(string) *linkMeter { return &linkMeter{} }

func (m *linkMeter) Sample() (speedMbps, dataGB float64) { return 0, 0 }
