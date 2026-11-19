#!/bin/sh
# Startskript für Knoten und Portal: Routen setzen, optional VPN starten, dann die Anwendung.
set -e

# Alles im Lab-Netz geht über die Firewall (das ist die Segmentierung).
ip route replace "${SUPERNET:-10.10.0.0/16}" via "$NODE_GW"
for net in $EXTRA_ROUTES; do
  ip route replace "$net" via "$NODE_GW"
done

case "$ROLE" in
  vpn-gateway|vpn-client)
    if [ -f /vpn/wg0.conf ]; then
      mkdir -p /etc/wireguard && cp /vpn/wg0.conf /etc/wireguard/wg0.conf && chmod 600 /etc/wireguard/wg0.conf
      # Der Tunnel ist optional: ohne /dev/net/tun läuft das Lab weiter, nur das VPN fehlt.
      wg-quick up wg0 || echo "WARNUNG: WireGuard konnte nicht gestartet werden (siehe docs/VPN.md)"
    fi
    ;;
esac

exec "$@"
