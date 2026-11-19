# Klinikum-Netlab

Komplettes Lab für ein Klinikum-Netz: Abteilungen als Zonen, Firewall mit Standard „alles verboten“,
Monitoring, Web-Oberfläche, VPN, Notfall-Isolation und automatische Prüfung, ob die Firewall wirklich
das tut, was die Policy sagt. **Alles entsteht aus einer Datei: `topology/klinikum.yml`.**

```
topology/klinikum.yml ──► tools/render.py ──► nftables · docker-compose · Prometheus · Alerts
   (einzige Wahrheit)                         Grafana-Dashboard · WireGuard · Prüfmatrix
```

## Schnellstart (Docker)

```bash
pip install -r requirements.txt
make up                     # rendert die Konfiguration und startet alles
```

| Was | Adresse |
|---|---|
| NetOps-Portal (Netzplan, Matrix, Firewall, Dienste, VPN, Alarme) | http://localhost:8080 |
| Grafana (Dashboard „Klinikum-Netz Übersicht“) | http://localhost:3000 (Anmeldung admin / klinikum, ansehen ohne Anmeldung) |
| Prometheus | http://localhost:9090 |
| Alertmanager | http://localhost:9093 |

Die Ports sind nur auf `127.0.0.1` gebunden. Das Portal hat keine Anmeldung und gehört nicht ins Netz.

## Zonen

mgmt (Monitoring) · server (KIS, PACS, LIS, Verzeichnisdienst) · data (Datenbank) · verwaltung · klinik (Ärzte, Pflege) ·
medgeraete (MRT, Infusion, EKG) · gast · dmz (Patientenportal, VPN-Gateway) · internet (simuliert, mit zwei VPN-Clients)

## Was man damit zeigen kann

1. **Segmentierung:** Das MRT darf Bilder an das PACS senden (DICOM 4242), sonst nirgends hin. Das Gast-WLAN sieht nur das Patientenportal.
2. **Policy as Code:** Eine Regel in der YAML ändern, `make render`, Regel erscheint in nftables, Matrix, Doku. `make check` bricht ab, wenn eine Sicherheitsaussage (`assertions`) verletzt wird.
3. **Drift-Erkennung:** Fügt jemand von Hand eine Regel hinzu, zeigt die Matrix rot und der Alarm `PolicyAbweichung` feuert.
4. **Notfall-Isolation:** Im Portal unter „Firewall“ eine Zone abschneiden, andere Zonen arbeiten weiter.
5. **VPN:** Drei Peers mit unterschiedlichen Rechten (Admin-Laptop nur Monitoring, Außenstelle und Dienst-Handy nur KIS). Zwei Ebenen: AllowedIPs und Firewall-Regel pro Peer.
5a. **VPN-Live:** Portal → VPN zeigt Karte (wer ist wo), Tunnel-Graph, Handshake, Traffic, Alarm bei unerwartetem Land (Demo: „Reise simulieren“). Grafana-Dashboard „Klinikum-VPN Live“ mit `prometheus_wireguard_exporter`.
6. **Monitoring:** Blackbox-Prüfungen (TCP, ICMP), Regelzähler der Firewall, Alarme mit Webhook ins Portal.

## Tests

| Befehl | Prüft |
|---|---|
| `make check` | Topologie gültig, alle Sicherheitsaussagen erfüllt, nft-Syntax |
| `make lint` | YAML |
| `make test` (root) | **Ende-zu-Ende ohne Docker**: echte nftables-Regeln in Network-Namespaces, echter Knoten-, Agent- und Portal-Code, 260 Verbindungen gegen die Policy, VPN-Live (mit Ersatz-`wg`), Drift, Isolation |
| `cd ansible && ansible-playbook site.yml` | Regeln per Ansible ausrollen (Container-Name über `FW_CONTAINER`) |

## Bekannte Grenzen

- Verkehr **innerhalb** einer Zone wird nicht gefiltert (alles in einer Bridge). Produktiv: private VLANs oder Host-Firewalls.
- Die Firewall arbeitet auf IP und Port, ohne Anwendungsprüfung (kein IDS, kein TLS-Inspection).
- Daten sind synthetisch. Keine echten Patientendaten verwenden.
- Die VPN-Schlüssel in `build/vpn` sind nur für das Lab. Neu erzeugen mit `rm -r build/vpn && make render`.
- Das Docker-Lab (inkl. echtem WireGuard, Exporter, Grafana, Prometheus, Karte im Browser) ist in der Entwicklungsumgebung **nicht gestartet** worden, siehe `docs/ARCHITEKTUR.md`, Abschnitt „Teststand“.

## Weiterführende Doku

- `docs/VPN-BETRIEB.md`: VPN in echt, Rollen, Rollout, Architektur eines Klinikums, Fehlersuche
- `docs/DEPLOYMENT.md`: Installation und Deployment Schritt für Schritt
- `docs/ARCHITEKTUR.md`, `docs/INTERVIEW.md`

## Anwendungen (Patientenportal, KIS mit Rollen, Backup)
Siehe `docs/ANWENDUNGEN.md`. Nach `make up`: http://localhost:8080 → **Anwendungen** und **Backup**. Tests: `make apptest`, `make test`.
