package egress

import "testing"

func TestClassifySite(t *testing.T) {
	cases := []struct {
		name      string
		servedBy  string
		exitLabel string
		peerExit  bool
		via       string
		label     string
		cloud     bool
	}{
		{"direct exit without servedBy", "", "Charon", false, "cloud", "Charon", true},
		{"direct exit with servedBy", "Charon", "Charon", false, "cloud", "Charon", true},
		{"friend exit", "Xavier", "Xavier", true, "friend", "Xavier", false},
		{"cloud relay", "", "", false, "cloud", "Cloud relay", true},
		{"aegis name", "aegis", "", false, "cloud", "Cloud relay", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			via, label, cloud := classifySite(tc.servedBy, tc.exitLabel, tc.peerExit)
			if via != tc.via || label != tc.label || cloud != tc.cloud {
				t.Fatalf("classifySite(%q, %q, %v) = (%q, %q, %v), want (%q, %q, %v)",
					tc.servedBy, tc.exitLabel, tc.peerExit, via, label, cloud, tc.via, tc.label, tc.cloud)
			}
		})
	}
}
