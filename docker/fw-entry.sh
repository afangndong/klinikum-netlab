#!/bin/sh
# Firewall-Container: Regeln laden, Routen für das VPN-Netz setzen, Agent starten.
set -e
nft -f /etc/nftables.conf
# FW_ROUTES, z. B. "10.99.0.0/24 via 10.10.70.11" (VPN-Pool liegt hinter dem Gateway)
if [ -n "$FW_ROUTES" ]; then
  ip route replace $FW_ROUTES
fi
exec "$@"
