// Package blockpage recognises the page a network filter serves in place of a
// site. Evidence rules share it so a client probe and the exit router agree on
// what a refusal looks like.
package blockpage

import "strings"

// Block pages are identified by structure, not prose. A school appliance can
// localise its wording, but the links it generates and the titles it uses stay
// the same. These signatures come from a real FortiGate page captured on an
// intercepting network: title "Web Filter Violation", heading "FortiGuard
// Intrusion Prevention - Access Blocked", a rating link to
// globalurl.fortinet.net, and a 403 over a trusted enterprise CA.
//
// A vendor name alone is not enough: a security site's front page can discuss
// FortiGuard. A signature therefore needs a block-page-only URL, a block-page
// title, or a refusal status together with the vendor name.
var urls = []struct{ name, marker string }{
	{"fortigate", "fortinet.net/rate/submit"},
	{"fortigate", "blocked.fortinet.com"},
	{"cisco-umbrella", "policy.cisco.com"},
}

var titles = []struct{ name, marker string }{
	{"fortigate", "web filter violation"},
	{"fortigate", "web page blocked"},
	{"fortigate", "intrusion prevention"},
	{"cisco-umbrella", "blocked by umbrella"},
}

var vendors = []struct{ name, marker string }{
	{"fortigate", "fortiguard"},
	{"fortigate", "fortinet"},
	{"bluecoat", "bluecoat"},
	{"sonicwall", "sonicwall"},
	{"untangle", "untangle"},
	{"palo-alto", "palo alto networks"},
}

// Signature names the appliance whose block page this is, or "" when the
// response does not look like one. The name is recorded as evidence, so a
// report says which filter produced the page.
func Signature(status int, title, body string) string {
	lower := strings.ToLower(body)
	for _, sig := range urls {
		if strings.Contains(lower, sig.marker) {
			return sig.name
		}
	}
	titleLower := normalizeTitle(title)
	for _, sig := range titles {
		if strings.Contains(titleLower, sig.marker) {
			return sig.name
		}
	}
	if status >= 400 {
		for _, sig := range vendors {
			if strings.Contains(lower, sig.marker) {
				return sig.name
			}
		}
	}
	return ""
}

func normalizeTitle(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

// Title returns the document title, trimmed.
func Title(body string) string {
	lower := strings.ToLower(body)
	open := strings.Index(lower, "<title")
	if open < 0 {
		return ""
	}
	gt := strings.Index(lower[open:], ">")
	if gt < 0 {
		return ""
	}
	start := open + gt + 1
	end := strings.Index(lower[start:], "</title>")
	if end < 0 {
		return ""
	}
	return strings.Join(strings.Fields(body[start:start+end]), " ")
}
