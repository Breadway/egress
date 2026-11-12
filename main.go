// Command egress is the DNS-over-HTTPS resolver and WireGuard exit client.
//
// Everything but this entry point lives in internal/egress; keeping the root
// package to a few lines makes the layout obvious and leaves room to split the
// internals into packages without touching the build entry point.
package main

import "egress/internal/egress"

func main() {
	egress.Main()
}
