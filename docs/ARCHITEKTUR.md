# Architektur

## Aufbau

- **fw** (Container, nftables): Router zwischen allen Zonen. `forward`-Policy `drop`. Erlaubt wird nur, was in der Policy steht, jede Regel hat einen Zähler und die Policy-ID als Kommentar. Das Set `isolated` schneidet ganze Zonen ab (Regel steht vor allen Freigaben).
- **Knoten** (je ein Container pro Host): bieten ihre Dienste an (HTTP oder TCP) und haben einen Messpunkt auf Port 7070 (nur aus mgmt erreichbar).
- **portal** (mgmt-hub): Web-Oberfläche und Prüfer. Prometheus, Grafana, Alertmanager und Blackbox teilen sich per `network_mode: service:portal` dessen Netzwerk. So steht das Monitoring „in“ der Zone mgmt, ohne Sonderrechte.
- **Zonen** sind Docker-Netze mit `internal: true`. Dadurch gibt es keinen Weg am Router vorbei. Nur das Portal hängt zusätzlich an einem `access`-Netz, damit die Oberfläche auf `localhost` erreichbar ist.

## Datenfluss der Prüfung

Das Portal fragt jeden Messpunkt: „Versuche diese Ziele“. Jeder Knoten verbindet sich aus **seiner** Zone. Die Antwort (verbunden oder nicht) wird gegen `T.expected_matrix()` verglichen, also gegen die gleiche Policy, aus der die Firewall erzeugt wurde. Abweichung = Fehler in Firewall oder Policy. Das Ergebnis geht als Metrik `lab_policy_mismatch` an Prometheus.

## VPN

Gateway `vpn-gw` in der DMZ (UDP 51820), Tunnelnetz 10.99.0.0/24. Die Firewall routet den Pool über das Gateway. Die Clients stehen in der Zone `internet` und verbinden sich zum Gateway. Pro Peer gilt: AllowedIPs begrenzt das Routing, eine Firewall-Regel mit Selektor `vpn_peer` begrenzt, was die Tunneladresse erreichen darf.

## Sicherheitsaussagen (`assertions`)

Sätze wie „Medizingeräte erreichen die Datenbank nicht“ stehen in der YAML und werden bei jedem Render geprüft. Eine Aussage, die auf nichts zutrifft, ist selbst ein Fehler (sonst wäre sie wertlos).

## Teststand

| Bereich | Status |
|---|---|
| Topologie-Validierung, Policy-Logik, Sicherheitsaussagen | getestet |
| nftables-Regeln (echtes `nft`, Namespaces) | getestet: 245 Verbindungen, Soll = Ist |
| Knoten-, Agent-, Portal-Code | getestet im Namespace-Test (inkl. Drift, Isolation, Token, Zähler) |
| UDP/51820 zum Gateway | getestet |
| `docker compose config`, nft-Syntax, Ansible-Syntaxprüfung | getestet |
| **Docker-Images bauen und starten** | **nicht getestet** (kein Docker-Daemon in der Entwicklungsumgebung) |
| VPN-Live: Agent `/wg`, Portal-Zuordnung, Standort, Reise-Simulation, Metriken `lab_vpn_*` | getestet mit Ersatz für `wg` (gleiches Dump-Format) |
| **WireGuard-Tunnel** | **nicht getestet** (im Namespace-Test nur nachgebildet: Clients senden mit der Tunneladresse) |
| **prometheus_wireguard_exporter** (Bau aus Quellen, Beschriftung `friendly_name`) | **nicht getestet** |
| **Portal-Karte (Leaflet im Browser)** | JavaScript-Syntax geprüft, **nicht im Browser angesehen** |
| **Grafana-Dashboard „Klinikum-VPN Live“ (Geomap, Traffic)** | JSON gültig, **nicht in Grafana geladen** |
| **Prometheus, Alertmanager, Grafana, Blackbox zur Laufzeit** | **nicht getestet**: Konfigurationen sind erzeugt und syntaktisch gültig, das Dashboard-JSON lädt, aber Abfragen und Alarme wurden nicht live gesehen |

Erste Handgriffe, falls etwas im Docker-Lab hakt: `docker compose logs fw portal`, `docker compose exec admin-laptop wg show`, unter `/dev/net/tun` im Host nachsehen (Docker Desktop und WSL brauchen ggf. Freigabe).

## Erweiterungsideen

Private VLANs oder Host-Firewalls für Verkehr innerhalb der Zonen, Syslog/Loki, IDS (Suricata) am Router, Zertifikatsbasierte Anmeldung am Portal, zweite Firewall (HA), ein Playbook, das echte Switches konfiguriert.
