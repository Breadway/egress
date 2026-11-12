#!/bin/sh
# Apply the tunnel shaper without the service, for a manual check.
# Usage: sudo ./deploy/wg-shape.sh
set -eu
tc qdisc del dev wg0 root 2>/dev/null || true
systemctl start wg-shape
tc class show dev wg0 | head -5
