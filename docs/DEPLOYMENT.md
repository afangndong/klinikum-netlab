# Installation und Deployment, Schritt für Schritt

Zielgruppe: Windows- oder Linux-Rechner, wenig Vorwissen über das Lab. Dauer erster Start: ca. 15 Minuten (der Bau des WireGuard-Exporters aus den Quellen dauert einige Minuten zusätzlich).

## Teil A: Lab lokal starten

**Schritt 1: Voraussetzungen**
- Windows: WSL2 mit Ubuntu (`wsl --install` in der PowerShell als Administrator, Neustart) und Docker Desktop mit „WSL-Integration“ für Ubuntu. Linux: Docker Engine mit dem Compose-Plugin.
- Python 3.11 oder neuer, `make`, `git`, `unzip` (in Ubuntu: `sudo apt install -y python3-venv make git unzip`).

**Schritt 2: Projekt entpacken**
```bash
unzip klinikum-netlab.zip && cd klinikum-netlab
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

**Schritt 3: Prüfen, ohne Docker**
```bash
make check        # Topologie, Sicherheitsaussagen, nft-Syntax
```
Erwartung: „21 Sicherheitsaussagen erfüllt“ und „nftables-Syntax ok“. (`nft` muss installiert sein: `sudo apt install -y nftables`.)

**Schritt 4: Starten**
```bash
make up           # erzeugt die Konfiguration, baut die Images, startet alles
docker compose ps # alle Dienste sollen "running" sein
```
Das erste Bauen dauert, besonders `wg-exporter` (Rust). Folgestarts sind schnell.

**Schritt 5: Ansehen** (Ports nur lokal)
| Seite | Adresse |
|---|---|
| Portal (Netzplan, Matrix, Firewall, Dienste, VPN, Alarme) | http://localhost:8080 |
| Grafana (zwei Dashboards: Klinikum-Netz, Klinikum-VPN Live) | http://localhost:3000 |
| Prometheus | http://localhost:9090 |
| Alertmanager | http://localhost:9093 |

**Schritt 6: Erwartetes Verhalten prüfen**
1. Portal → Erreichbarkeit: nach ca. einer Minute „0 Abweichungen“.
2. Portal → VPN: drei Peers, aktiv nach wenigen Sekunden (Handshake). Falls „getrennt“: `docker compose logs vpn-gw admin-laptop` ansehen, siehe Teil E.
3. Portal → VPN → „Reise simulieren“ → São Paulo für `admin-laptop`: Alarm „unerwartetes Land“, in Prometheus/Alertmanager nach kurzer Zeit sichtbar.
4. Portal → Firewall → Zone `klinik` isolieren: Stationsrechner erreichen das KIS nicht mehr, Verwaltung schon. Danach freigeben.
5. Eine Regel von Hand ändern, um Drift zu zeigen: `docker compose exec fw nft insert rule ip klinikum forward position 0 ip saddr 10.10.50.0/24 ip daddr 10.10.20.10 tcp dport 8080 accept`. Nach der nächsten Matrix-Prüfung rot, Alarm „PolicyAbweichung“. Zurück mit `docker compose restart fw` (lädt die Regeln aus der Policy neu).

**Schritt 7: Aufräumen**
```bash
make down                 # stoppt, behält Daten
docker compose down -v    # stoppt und löscht Volumes
```

## Teil B: Ohne Docker testen (Ende-zu-Ende)
```bash
sudo .venv/bin/python tools/netns_test.py
```
Baut das Netz in Linux-Namespaces, lädt die echten Firewall-Regeln und prüft 260 Verbindungen, VPN-Live mit Ersatz-`wg`, Drift, Isolation. Erwartung: „47 von 47 Prüfungen bestanden“. Läuft nur unter Linux/WSL2 mit root.

## Teil C: Änderungen vornehmen (so arbeitet man damit)
1. `topology/klinikum.yml` ändern (neuer Host, neue Regel, neuer VPN-Peer).
2. `make check`: bricht ab, wenn eine Sicherheitsaussage verletzt wird.
3. `make up` (rendert neu, startet geänderte Container).
4. Portal → Erreichbarkeit prüfen. Nach jeder Änderung sollte „0 Abweichungen“ stehen.

**Neuen VPN-Peer anlegen:** Eintrag unter `vpn.peers` (Adresse, Zonen, Nutzer, Gerät, Standort, erlaubte Länder), Client-Host in der Zone `internet` mit `vpn_peer`, Policy-Eintrag mit Selektor `vpn_peer`, Assertions für erlaubt/verboten. Die Schlüssel erzeugt `make render` (im Lab; in Produktion erzeugt sie das Gerät selbst).

## Teil D: Auf einen Server bringen (z. B. VM mit Ubuntu 24.04)
1. VM mit mindestens 2 vCPU, 4 GB RAM, 20 GB Platte. Zugang nur per SSH-Schlüssel.
2. Docker installieren (offizielle Anleitung von docs.docker.com) und `sudo usermod -aG docker $USER`.
3. Projekt kopieren, Teile A, Schritt 2 bis 4 ausführen.
4. Die Oberflächen sind nur auf `127.0.0.1` gebunden. Zugriff per SSH-Tunnel: `ssh -L 8080:127.0.0.1:8080 -L 3000:127.0.0.1:3000 user@server`. **Das Portal nicht ins Netz stellen**: keine Anmeldung, Notfall-Isolation per Klick.
5. Eigene Zugangsdaten setzen: `export LAB_TOKEN=<zufällig>` und `export GRAFANA_PASSWORD=<zufällig>` vor `make up`.
6. Host-Firewall (`ufw`) erlaubt nur SSH.

## Teil E: Fehlersuche beim Start
| Symptom | Ursache und Abhilfe |
|---|---|
| `wg-quick up wg0` schlägt fehl (Logs von `vpn-gw`) | Kernelmodul oder `/dev/net/tun` fehlt. Docker Desktop/WSL2 aktuell halten. Der Container fällt auf `wireguard-go` zurück, wenn installiert. Das Lab läuft ohne VPN weiter. |
| Peers bleiben „getrennt“ | `docker compose exec vpn-gw wg show`: Handshake? Wenn nein, UDP 51820 zwischen Client- und Gateway-Zone prüfen (Regel P11), Schlüssel neu erzeugen (`rm -r build/vpn && make up`). |
| Matrix zeigt Abweichungen | Portal → Erreichbarkeit → „nur Abweichungen“. Meist fehlt ein Dienst (Container down) oder eine Regel wurde von Hand geändert. |
| `wg-exporter` startet nicht | `docker compose logs wg-exporter`. Der Bau braucht Internet (crates.io). Ohne Exporter fehlen nur die Traffic-Panels und der Handshake-Alarm. |
| Grafana-Karte leer | Panel „Wer ist wo?“ braucht `lab_vpn_peer_location` aus dem Portal. In Prometheus prüfen: `lab_vpn_peer_location`. |
| Portal-Karte grau | Der Browser braucht Internet für Leaflet und Kacheln. Tabelle funktioniert trotzdem. |
| Port belegt | Anderen Dienst beenden oder die Ports in `tools/render.py` ändern. |
| Docker Desktop ohne WSL-Integration | Einstellungen → Resources → WSL Integration → Ubuntu aktivieren. |

## Teil F: Vom Lab zur Produktion (Reihenfolge)
1. **Anforderungen und Schutzbedarf** mit Fachbereichen und Datenschutz klären.
2. **Zonenmodell** festlegen (Lab als Vorlage), VLANs und Adressplan.
3. **Firewall-Hardware oder -Cluster**, Regeln aus der Policy-Datei erzeugen.
4. **VPN-Lösung wählen** (mit Benutzerverwaltung und MFA), Gateways redundant in der DMZ.
5. **Identität und Geräteverwaltung** anbinden (Verzeichnisdienst, MDM, Zertifikate).
6. **Monitoring und Protokollierung** (Prometheus/Grafana plus SIEM, Alarme an Rufbereitschaft).
7. **CI/CD**: Repository, Pull-Request-Pflicht, Policy-Checks, Ansible gegen Test- und danach Produktivumgebung.
8. **Pilot, dann stufenweise Einführung** (siehe `docs/VPN-BETRIEB.md`, Abschnitt 7).
9. **Backup und Wiederanlauf** üben, Notfallhandbuch.
10. **Dokumentation und Schulung**, regelmäßige Rezertifizierung der Zugänge.

## Teil G: CI/CD einrichten
- **GitHub Actions:** Repository auf GitHub, `.github/workflows/ci.yml` läuft bei jedem Push: Lint, Policy-Check, Compose-Prüfung, Ende-zu-Ende-Test, Ansible-Syntax.
- **Jenkins:** neue Pipeline „aus SCM“, `Jenkinsfile` im Repository. Der Agent braucht Docker, `nft` und `sudo -n` für den Namespace-Test.
- **Deployment per Ansible:** `cd ansible && FW_CONTAINER=klinikum-lab-fw-1 ansible-playbook site.yml` (Lab). In Produktion: SSH-Inventar statt Docker-Verbindung, Schlüssel im Geheimnis-Speicher, nie im Repository.
