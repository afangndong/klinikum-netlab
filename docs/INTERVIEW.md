# Kurzvorstellung für das Gespräch (Ortenau Klinikum, IT-Netzwerkspezialist)

**In einem Satz:** Ich habe ein Klinikum-Netz als Code nachgebaut: Eine YAML-Datei beschreibt Zonen, Dienste und Freigaben, daraus entstehen Firewall-Regeln, Monitoring und Tests, und das Lab prüft sich selbst, ob die Firewall wirklich das tut, was die Policy sagt.

## Stellenanzeige gegen Lab

| Anforderung | Im Lab |
|---|---|
| Enterprise-Firewalls, Segmentierung | Default-Deny-Firewall, 9 Zonen, Regeln mit ID und Zähler |
| VPN | WireGuard mit Peers unterschiedlicher Rechte |
| Infrastructure as Code, Ansible, Python | Generator in Python, Ansible-Rolle, Jenkins/GitHub-Actions |
| Monitoring | Prometheus, Alertmanager, Blackbox, Grafana |
| Betrieb und Störung | Notfall-Isolation, Drift-Erkennung, Alarmwebhook |

## Fragen, die kommen können

1. **Warum Zonen in einer Klinik?** Medizingeräte laufen oft mit alter Software, können nicht gepatcht werden und dürfen nur das Nötigste erreichen (MRT → PACS). Ein befallener Stationsrechner darf nicht an die Datenbank.
2. **Was hast du getestet und was nicht?** Siehe `docs/ARCHITEKTUR.md`, Abschnitt Teststand. Ehrlich benennen: Regeln und Code ja, echtes Docker/WireGuard/Grafana-Laufzeitverhalten noch nicht live gesehen.
3. **Was ist die Grenze?** Verkehr innerhalb einer Zone ist nicht gefiltert, keine Anwendungsprüfung.
4. **Wie rolltest du Änderungen produktiv aus?** Änderung in der YAML, Pull Request, CI prüft Sicherheitsaussagen, Ansible rollt aus, danach läuft die Matrix als Abnahmetest.
5. **Was ist bei einem Befall?** Betroffene Zone isolieren, Logs und Zähler ansehen, Ursache klären, freigeben.

## Nicht behaupten

Keine Erfahrung mit KRITIS-Audits, B3S oder echten Medizingeräten, wenn sie nicht stimmt. Das Lab ist ein Lernprojekt mit synthetischen Daten.
