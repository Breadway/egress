package main

import (
	"fmt"
)

// fleet joins the three registries so every admin page answers from the same
// data: an application points at a device, a device may have a login from the
// pre-token era, and a report is keyed by the device's public key.
//
// Before this, each page read its own registry and drew its own conclusions,
// which is how an application could say "installed" while the Logins page said
// "no report" for the machine that installed it.
type fleet struct {
	apps       []application
	devices    []device
	users      map[string]user
	devByID    map[string]device
	devByPub   map[string]device
	appByDev   map[string]application
	loginByPub map[string]string
}

func (s *server) loadFleet() *fleet {
	f := &fleet{
		apps:       s.loadApplications(),
		users:      s.loadUsers(),
		devByID:    map[string]device{},
		devByPub:   map[string]device{},
		appByDev:   map[string]application{},
		loginByPub: map[string]string{},
	}
	s.devicesMu.Lock()
	reg, _ := loadDevices(s.devicesPath())
	s.devicesMu.Unlock()
	f.devices = reg.Devices
	for _, d := range f.devices {
		f.devByID[d.ID] = d
		if d.PubKey != "" {
			f.devByPub[d.PubKey] = d
		}
	}
	for _, a := range f.apps {
		if a.DeviceID != "" {
			f.appByDev[a.DeviceID] = a
		}
	}
	for name, u := range f.users {
		if u.Peer != "" {
			f.loginByPub[u.Peer] = name
		}
	}
	return f
}

// appState is the single status vocabulary for an application, derived from the
// device it points at rather than from a flag of its own.
func (f *fleet) appState(a application) (chip, class string) {
	switch {
	case a.ProvisionError != "":
		return "failed", "bad"
	case a.DeviceID == "" && a.Reviewed:
		return "approved", ""
	case a.DeviceID == "":
		return "waiting", "new"
	}
	if d, ok := f.devByID[a.DeviceID]; ok && d.Status == "bound" {
		return "installed", "ok"
	}
	return "ready", "ok"
}

// appDevice returns the device an application prepared, if it still exists.
func (f *fleet) appDevice(a application) (device, bool) {
	d, ok := f.devByID[a.DeviceID]
	return d, ok
}

// deviceApp returns the application a device came from, if any.
func (f *fleet) deviceApp(d device) (application, bool) {
	a, ok := f.appByDev[d.ID]
	return a, ok
}

// deviceLogin returns the legacy login whose installer carried this device's
// key, if one exists.
func (f *fleet) deviceLogin(d device) (string, bool) {
	name, ok := f.loginByPub[d.PubKey]
	return name, ok
}

// fleetCounts are the numbers every page shows, computed once from the join.
func (f *fleet) counts() (waiting, ready, installed, attention int) {
	for _, a := range f.apps {
		switch chip, _ := f.appState(a); chip {
		case "waiting":
			waiting++
		case "ready":
			ready++
		case "installed":
			installed++
		case "failed":
			attention++
		}
	}
	return
}

// boundDevices and openInvites are the device-side numbers.
func (f *fleet) boundDevices() (bound, open int) {
	for _, d := range f.devices {
		if d.Status == "bound" {
			bound++
		} else {
			open++
		}
	}
	return
}

// deviceReportCell is the report pill for a device, shared by every page.
func (s *server) deviceReportCell(pubkey string) string {
	rep, ok := s.latestReport(pubkey)
	if !ok {
		return `<span class="pill">no report</span>`
	}
	label, class := effectiveStatus(rep.Report)
	return fmt.Sprintf(`<span class="pill %s">%s</span><span class="cell-sub">%s &middot; %s</span>`,
		class, esc(label), esc(timeAgo(rep.Received)), esc(rep.Report.Version))
}

// deviceStatusMap is the app.DeviceID -> status lookup the overview table uses.
func (f *fleet) deviceStatusMap() map[string]string {
	out := map[string]string{}
	for id, d := range f.devByID {
		out[id] = d.Status
	}
	return out
}

// fleetTableHTML is the Overview's device list. It comes from the device
// registry, not from the legacy login rows, so the number in the stat above it
// and the rows below it always describe the same machines.
func (s *server) fleetTableHTML(f *fleet) string {
	if len(f.devices) == 0 {
		return `<div class="table-wrap"><div class="empty"><strong>No devices yet.</strong>Approve an application to create an invite.</div></div>`
	}
	var b []byte
	b = append(b, `<div class="table-wrap compact"><table><thead><tr><th>Device</th><th>Label</th><th>Address</th><th>Status</th><th>Report</th><th>Application</th></tr></thead><tbody>`...)
	for _, d := range f.devices {
		app := `<span class="muted">&mdash;</span>`
		if a, ok := f.deviceApp(d); ok {
			app = `<a href="/admin/applications/` + esc(a.ID) + `">` + esc(a.Name) + `</a>`
		}
		b = append(b, `<tr><td><a href="/admin/devices/`+esc(d.ID)+`"><code>`+esc(d.ID)+`</code></a></td><td>`+
			esc(d.Label)+`</td><td>`+esc(d.IP)+`</td><td>`+esc(d.Status)+`</td><td>`+
			s.deviceReportCell(d.PubKey)+`</td><td>`+app+`</td></tr>`...)
	}
	b = append(b, `</tbody></table></div>`...)
	return string(b)
}
