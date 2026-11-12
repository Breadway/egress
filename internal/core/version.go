package core

// BuildVersion is the release version, set at build time:
//
//	go build -ldflags "-X egress/internal/core.BuildVersion=1.2.3"
var BuildVersion = "0.0.0"
