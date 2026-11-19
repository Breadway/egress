package egress

import (
	"egress/internal/core"
	"egress/internal/health"
)

// Health checks, reports and the readiness marker live in internal/health so
// the supervisor and the CLI can share them.
type checkResults = health.Results

type deviceIdentity = health.DeviceIdentity

var (
	runChecks           = health.RunChecks
	verifyAll           = health.VerifyAll
	describeSplit       = health.DescribeSplit
	buildReport         = health.BuildReport
	sendReport          = health.SendReport
	spoolReport         = health.SpoolReport
	checkSupervisorLive = health.CheckSupervisorLive
	checkSystemDNS      = health.CheckSystemDNS
	readyMarkerMaxAge   = health.ReadyMarkerMaxAge
	flushPendingReport  = health.FlushPendingReport
	loadDeviceIdentity  = health.LoadDeviceIdentity
	saveDeviceIdentity  = health.SaveDeviceIdentity
	removeReadyMarker   = health.RemoveReadyMarker
	writeReadyMarker    = health.WriteReadyMarker
	writeDiagnose       = health.WriteDiagnose
)

var _ = core.BuildVersion
