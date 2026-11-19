# Anwendungen im Lab: Patientenportal, KIS, Backup

Starten: `make up`, dann `http://localhost:8080` öffnen und oben auf **Anwendungen** klicken.
Jede Karte öffnet eine Anwendung so, als säße der Browser auf dem genannten Gerät. Die Anfrage läuft durch die echte Firewall.

## Zwei Schutzebenen
1. **Netz:** Darf das Gerät den Dienst erreichen? (Firewall-Regeln, z. B. P09 Gast → Patientenportal, P10 Portal → KIS, P15 VPN → KIS)
2. **Rolle:** Was darf der angemeldete Benutzer im Dienst? (RBAC, Behandlungsbezug, Notfallzugriff mit Begründung)

## Zugangsdaten (nur Lab, absichtlich sichtbar)
| Rolle | Benutzer / Passwort | Darf | Darf nicht |
|---|---|---|---|
| Patient (Portal) | P-1001 / PIN 1234 (auch P-1002 / 2345, P-1003 / 3456) | eigene Akte, Termine buchen und absagen, eigene Rechnungen, Archiv | fremde Daten |
| Arzt | dr.beispiel / arzt-lab | Patienten mit Behandlungsbezug, Befunde, Termine, Archiv, Notfallzugriff | Abrechnung |
| Pflege | schwester.test / pflege-lab | Akte ohne Befunde, Termine ansehen | Befunde, Notfallzugriff |
| Empfang | empfang.lab / empfang-lab | Termine anlegen und ändern | Akte, Abrechnung |
| Abrechnung | abrechnung.lab / abrechnung-lab | Rechnungen, Bezahlt-Markierung | Diagnosen, Termine |
| IT-Admin | admin.lab / admin-lab | Protokoll | alle Patientendaten |

Sicherheitsmerkmale: CSRF-Token, HttpOnly/SameSite-Cookies, Sitzungsablauf, Sperre nach 5 Fehlversuchen in 60 s, Protokoll aller Zugriffe inkl. VERWEIGERT.

## Backup und Ransomware (Seite Backup)
- **Szenario A:** „unveränderlich“ aus → Angriff → Backups gelöscht → keine Wiederherstellung.
- **Szenario B:** „unveränderlich“ an → Angriff → Backups überleben → Wiederherstellung, Verlust = Änderungen seit letztem Backup (RPO), Dauer wird gemessen (RTO).
- Wiederherstellungstest prüft die SHA-256-Prüfsumme. Automatisches Backup alle `BACKUP_INTERVAL` Sekunden (Standard 300).
- Alarme: BackupZuAlt, KisDatenGesperrt, BackupNichtUnveraenderlich (Grafana-Panels 10–12).
- Grenzen: „unveränderlich“ ist Programmlogik. Real: Object Lock / Retention Lock, getrennte Admin-Konten, Offline-Kopie (3-2-1-1-0).

## Netz-Szenarien zum Üben
- Zone `server` isolieren → Patientenportal zeigt „Gerade nicht erreichbar, Ihre Daten sind sicher“.
- Gast → KIS und MRT → KIS: Verbindung wird verworfen, bevor eine Anmeldung möglich ist.

## Ehrliche Grenzen
Alle Daten sind synthetisch. Keine echte Benutzerverzeichnis-Anbindung, kein MFA, Portal-Admin ohne Anmeldung. Getestet: `make apptest` (81 Prüfungen, lokal) und `make test` (71 Prüfungen mit echter nftables-Firewall in Namespaces). Der Docker-Start der neuen Dienste ist nicht in Docker getestet, nur im Namespace-Aufbau mit denselben Programmen.
