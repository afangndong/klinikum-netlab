#!/usr/bin/env python3
"""Erzeugt aus topology/klinikum.yml alle Konfigurationen.

    python tools/render.py            # schreibt nach ./build und ./docker-compose.yml
    python tools/render.py --check    # nur prüfen, nichts schreiben

Erzeugt:
  build/fw/nftables.conf          Firewall-Regeln
  build/policy.json               Zonen, Regeln, erwartete Testmatrix
  docker-compose.yml              Gesamtes Lab
  build/prometheus/*              Prometheus, Alert-Regeln, Blackbox, Alertmanager
  build/grafana/provisioning/*    Datenquelle und Dashboard
  build/vpn/*                     WireGuard-Konfigurationen und Schlüssel (nur Lab)
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from netlab import topology as T  # noqa: E402

BUILD = ROOT / "build"
NODE_IMAGE = "klinikum-lab/node:1.0"
FW_IMAGE = "klinikum-lab/fw:1.0"
PORTAL_IMAGE = "klinikum-lab/portal:1.0"


# --------------------------------------------------------------------------
# Firewall
# --------------------------------------------------------------------------
def _addr(kw: str, cidrs: list[str]) -> str:
    return f"ip {kw} {cidrs[0]}" if len(cidrs) == 1 else f"ip {kw} {{ {', '.join(cidrs)} }}"


def nft_lines(rules: list[dict]) -> list[str]:
    lines = []
    for r in rules:
        head = f"{_addr('saddr', r['src'])} {_addr('daddr', r['dst'])}"
        if r["proto"] == "icmp":
            match = "icmp type echo-request"
        else:
            ports = r["ports"]
            pset = str(ports[0]) if len(ports) == 1 else "{ " + ", ".join(map(str, ports)) + " }"
            match = f"{r['proto']} dport {pset}"
        lines.append(f'{head} {match} counter accept comment "{r["id"]}"')
    return lines


def render_nft(t: dict) -> str:
    rules = nft_lines(T.expand_rules(t))
    mgmt = t["zones"]["mgmt"]["cidr"]
    body = "\n    ".join(rules)
    return f"""#!/usr/sbin/nft -f
# GENERIERT aus topology/klinikum.yml. Nicht von Hand ändern.
flush ruleset

table ip klinikum {{
  # Notfall-Isolation: Zonen in diesem Set werden komplett abgeschnitten.
  set isolated {{
    type ipv4_addr
    flags interval
  }}

  chain input {{
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif "lo" accept
    icmp type echo-request accept
    ip saddr {mgmt} tcp dport {t['firewall']['api_port']} accept comment "fw-agent"
  }}

  chain forward {{
    type filter hook forward priority 0; policy drop;
    ip saddr @isolated counter drop comment "ISOLATED"
    ip daddr @isolated counter drop comment "ISOLATED"
    ct state established,related accept
    {body}
    counter drop comment "default-deny"
  }}

  chain output {{
    type filter hook output priority 0; policy accept;
  }}
}}
"""


# --------------------------------------------------------------------------
# Docker Compose
# --------------------------------------------------------------------------
def render_compose(t: dict) -> dict:
    fw_octet = t["firewall"]["host_octet"]
    zones = t["zones"]
    networks: dict = {}
    for z, zc in zones.items():
        net = T.ipaddress.ip_network(zc["cidr"])
        networks[f"z_{z}"] = {
            "driver": "bridge",
            "internal": True,
            "ipam": {"config": [{"subnet": zc["cidr"], "gateway": str(net.network_address + 254)}]},
            "labels": {"lab.vlan": str(zc["vlan"]), "lab.title": zc["title"]},
        }
    networks["access"] = {"driver": "bridge"}

    vpn = t["vpn"]
    gw = vpn["gateway"]
    gw_ip = t["hosts"][gw]["ip"]
    pool = vpn["pool"]

    services: dict = {}
    services["fw"] = {
        "image": FW_IMAGE,
        "build": {"context": ".", "dockerfile": "docker/Dockerfile.fw"},
        "hostname": "fw",
        "cap_add": ["NET_ADMIN"],
        "sysctls": {"net.ipv4.ip_forward": "1", "net.ipv4.conf.all.rp_filter": "0", "net.ipv4.conf.default.rp_filter": "0"},
        "environment": {
            "LAB_TOKEN": "${LAB_TOKEN:-klinikum-lab}",
            "FW_ROUTES": f"{pool} via {gw_ip}",
        },
        "volumes": ["./build/fw/nftables.conf:/etc/nftables.conf:ro", "./build/policy.json:/config/policy.json:ro"],
        "networks": {f"z_{z}": {"ipv4_address": T.zone_gateway(t, z)} for z in zones},
        "restart": "unless-stopped",
    }

    hub = next(h for h, hc in t["hosts"].items() if hc.get("kind") == "hub")
    hub_cfg = t["hosts"][hub]
    ports = [f"127.0.0.1:{s['port']}:{s['port']}" for s in hub_cfg["services"]] + ["127.0.0.1:9093:9093"]
    services["portal"] = {
        "image": PORTAL_IMAGE,
        "build": {"context": ".", "dockerfile": "docker/Dockerfile.portal"},
        "hostname": hub,
        "cap_add": ["NET_ADMIN"],
        "sysctls": {"net.ipv4.ping_group_range": "0 2147483647"},
        "environment": {
            "LAB_TOKEN": "${LAB_TOKEN:-klinikum-lab}",
            "NODE_GW": T.zone_gateway(t, hub_cfg["zone"]),
            "NODE_IP": hub_cfg["ip"],
            "EXTRA_ROUTES": pool,
            "FW_URL": f"http://{T.zone_gateway(t, hub_cfg['zone'])}:{t['firewall']['api_port']}",
        },
        "volumes": ["./topology:/config/topology:ro", "./build:/config/build:ro"],
        "ports": ports,
        "networks": {f"z_{hub_cfg['zone']}": {"ipv4_address": hub_cfg["ip"]}, "access": {}},
        "depends_on": ["fw"],
        "restart": "unless-stopped",
    }
    # Monitoring-Werkzeuge teilen sich den Netzwerk-Namespace des Portals (= ein Host in Zone mgmt).
    shared = {"network_mode": "service:portal", "depends_on": ["portal"], "restart": "unless-stopped"}
    services["prometheus"] = {
        **shared, "image": "prom/prometheus:v2.55.1",
        "command": ["--config.file=/etc/prometheus/prometheus.yml", "--web.listen-address=0.0.0.0:9090",
                    "--storage.tsdb.retention.time=2d"],
        "volumes": ["./build/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro",
                    "./build/prometheus/alerts.yml:/etc/prometheus/alerts.yml:ro"],
    }
    services["alertmanager"] = {
        **shared, "image": "prom/alertmanager:v0.27.0",
        "command": ["--config.file=/etc/alertmanager/alertmanager.yml", "--web.listen-address=0.0.0.0:9093"],
        "volumes": ["./build/prometheus/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro"],
    }
    services["blackbox"] = {
        **shared, "image": "prom/blackbox-exporter:v0.25.0",
        "command": ["--config.file=/etc/blackbox/blackbox.yml", "--web.listen-address=0.0.0.0:9115"],
        "volumes": ["./build/prometheus/blackbox.yml:/etc/blackbox/blackbox.yml:ro"],
    }
    services["grafana"] = {
        **shared, "image": "grafana/grafana:11.3.0",
        "environment": {
            "GF_SECURITY_ADMIN_PASSWORD": "${GRAFANA_PASSWORD:-klinikum}",
            "GF_AUTH_ANONYMOUS_ENABLED": "true",
            "GF_AUTH_ANONYMOUS_ORG_ROLE": "Viewer",
            "GF_USERS_DEFAULT_THEME": "light",
        },
        "volumes": ["./build/grafana/provisioning:/etc/grafana/provisioning:ro"],
    }

    for name, hc in t["hosts"].items():
        if hc.get("kind") == "hub":
            continue
        zone = hc["zone"]
        role = hc.get("role", "node")
        env = {
            "NODE_NAME": name,
            "NODE_ZONE": zone,
            "NODE_IP": hc["ip"],
            "NODE_TITLE": hc["title"],
            "NODE_DESCRIPTION": hc["description"],
            "NODE_GW": T.zone_gateway(t, zone),
            "NODE_SERVICES": json.dumps(hc["services"], ensure_ascii=False),
            "AGENT_PORT": str(t["agent_port"]),
            "ROLE": role,
            "LAB_TOKEN": "${LAB_TOKEN:-klinikum-lab}",
        }
        kinds = {sv.get("data") for sv in hc["services"]}
        if "kis" in kinds or "patientportal" in kinds:
            env["PORTAL_KEY"] = "${PORTAL_KEY:-portal-lab-key}"
        if "kis" in kinds:
            env["BACKUP_INTERVAL"] = "${BACKUP_INTERVAL:-300}"
        if "patientportal" in kinds:
            kh = next(h for h in t["hosts"].values() if any(sv.get("data") == "kis" for sv in h["services"]))
            kp = next(sv["port"] for sv in kh["services"] if sv.get("data") == "kis")
            env["KIS_URL"] = f"http://{kh['ip']}:{kp}"
        svc = {
            "image": NODE_IMAGE,
            "build": {"context": ".", "dockerfile": "docker/Dockerfile.node"},
            "hostname": name,
            "cap_add": ["NET_ADMIN"],
            "environment": env,
            "networks": {f"z_{zone}": {"ipv4_address": hc["ip"]}},
            "depends_on": ["fw"],
            "restart": "unless-stopped",
        }
        if role not in ("vpn-gateway", "vpn-client"):
            env["EXTRA_ROUTES"] = pool
        if role == "vpn-gateway":
            svc["devices"] = ["/dev/net/tun:/dev/net/tun"]
            svc["sysctls"] = {"net.ipv4.ip_forward": "1", "net.ipv4.conf.all.rp_filter": "0"}
            svc["volumes"] = ["./build/vpn/wg0.conf:/vpn/wg0.conf:ro"]
        if role == "vpn-client":
            svc["devices"] = ["/dev/net/tun:/dev/net/tun"]
            svc["volumes"] = [f"./build/vpn/{hc['vpn_peer']}.conf:/vpn/wg0.conf:ro"]
        services[name] = svc

    # prometheus_wireguard_exporter teilt sich den Netzwerk-Namespace des VPN-Gateways (liest wg0, Port 9586).
    services["wg-exporter"] = {
        "image": "klinikum-lab/wg-exporter:1.0",
        "build": {"context": ".", "dockerfile": "docker/Dockerfile.wgexporter"},
        "network_mode": f"service:{gw}",
        "cap_add": ["NET_ADMIN"],
        "volumes": ["./build/vpn/wg0.conf:/etc/wireguard/wg0.conf:ro"],
        "depends_on": [gw],
        "restart": "unless-stopped",
    }

    return {"name": t["name"], "services": services, "networks": networks}


# --------------------------------------------------------------------------
# Monitoring
# --------------------------------------------------------------------------
def render_prometheus(t: dict) -> dict:
    agents = [
        {"targets": [f"{hc['ip']}:{t['agent_port']}"], "labels": {"host": h, "zone": hc["zone"]}}
        for h, hc in t["hosts"].items() if hc.get("kind") != "hub"
    ]
    fw_ip = T.zone_gateway(t, "mgmt")
    tcp_targets, icmp_targets = [], []
    for h, hc in t["hosts"].items():
        icmp_targets.append({"targets": [hc["ip"]], "labels": {"host": h, "zone": hc["zone"]}})
        for s in hc["services"]:
            if s["kind"] in ("http", "tcp"):
                tcp_targets.append({
                    "targets": [f"{hc['ip']}:{s['port']}"],
                    "labels": {"host": h, "zone": hc["zone"], "service": s["name"]},
                })
    relabel = [
        {"source_labels": ["__address__"], "target_label": "__param_target"},
        {"source_labels": ["__param_target"], "target_label": "instance"},
        {"target_label": "__address__", "replacement": "localhost:9115"},
    ]
    return {
        "global": {"scrape_interval": "15s", "evaluation_interval": "15s"},
        "rule_files": ["/etc/prometheus/alerts.yml"],
        "alerting": {"alertmanagers": [{"static_configs": [{"targets": ["localhost:9093"]}]}]},
        "scrape_configs": [
            {"job_name": "lab-nodes", "static_configs": agents},
            {"job_name": "lab-fw", "static_configs": [{"targets": [f"{fw_ip}:{t['firewall']['api_port']}"], "labels": {"host": "fw"}}]},
            {"job_name": "lab-portal", "static_configs": [{"targets": ["localhost:8080"], "labels": {"host": "mgmt-hub"}}]},
            {"job_name": "wireguard", "static_configs": [{"targets": [f"{t['hosts'][t['vpn']['gateway']]['ip']}:9586"],
                                                          "labels": {"host": t["vpn"]["gateway"]}}]},
            {"job_name": "blackbox-tcp", "metrics_path": "/probe", "params": {"module": ["tcp_connect"]},
             "static_configs": tcp_targets, "relabel_configs": relabel},
            {"job_name": "blackbox-icmp", "metrics_path": "/probe", "params": {"module": ["icmp"]},
             "static_configs": icmp_targets, "relabel_configs": relabel},
        ],
    }


ALERTS = {
    "groups": [{
        "name": "klinikum-netz",
        "rules": [
            {"alert": "HostNichtErreichbar", "expr": 'up{job="lab-nodes"} == 0', "for": "1m",
             "labels": {"severity": "critical"},
             "annotations": {"summary": "Knoten {{ $labels.host }} (Zone {{ $labels.zone }}) antwortet nicht"}},
            {"alert": "DienstNichtErreichbar", "expr": 'probe_success{job="blackbox-tcp"} == 0', "for": "1m",
             "labels": {"severity": "warning"},
             "annotations": {"summary": "Dienst {{ $labels.service }} auf {{ $labels.host }} ist vom Mgmt-Hub nicht erreichbar"}},
            {"alert": "FirewallNichtErreichbar", "expr": 'up{job="lab-fw"} == 0', "for": "30s",
             "labels": {"severity": "critical"},
             "annotations": {"summary": "Der Firewall-Agent antwortet nicht. Regeln und Zähler sind blind."}},
            {"alert": "ZoneIsoliert", "expr": "lab_fw_zone_isolated == 1", "for": "0m",
             "labels": {"severity": "critical"},
             "annotations": {"summary": "Zone {{ $labels.zone }} ist per Notfall-Isolation abgeschnitten"}},
            {"alert": "VieleVerworfeneVerbindungen", "expr": 'rate(lab_fw_rule_packets_total{rule="default-deny"}[2m]) > 15', "for": "2m",
             "labels": {"severity": "warning"},
             "annotations": {"summary": "Ungewöhnlich viele verworfene Pakete. Mögliche Ursachen: Portscan, falsche Regel, Fehlkonfiguration."}},
            {"alert": "VpnExporterNichtErreichbar", "expr": 'up{job="wireguard"} == 0', "for": "1m",
             "labels": {"severity": "warning"},
             "annotations": {"summary": "WireGuard-Exporter antwortet nicht: keine VPN-Zahlen im Dashboard"}},
            {"alert": "VpnGatewayNichtErreichbar", "expr": "lab_vpn_gateway_reachable == 0", "for": "1m",
             "labels": {"severity": "critical"},
             "annotations": {"summary": "VPN-Gateway nicht abfragbar (wg0 down oder Agent weg)"}},
            {"alert": "VpnPeerOhneHandshake", "expr": "(time() - wireguard_latest_handshake_seconds) > 180", "for": "3m",
             "labels": {"severity": "warning"},
             "annotations": {"summary": "VPN-Peer {{ $labels.friendly_name }} {{ $labels.allowed_ips }} ohne Handshake seit über 3 Minuten (getrennt oder nie verbunden)"}},
            {"alert": "VpnPeerUnerwartetesLand", "expr": "lab_vpn_peer_geo_unexpected == 1", "for": "0m",
             "labels": {"severity": "critical"},
             "annotations": {"summary": "VPN-Peer {{ $labels.peer }} verbindet sich aus {{ $labels.country }}, nicht aus einem erlaubten Land"}},
            {"alert": "BackupZuAlt", "expr": "lab_backup_age_seconds > 900", "for": "1m",
             "labels": {"severity": "warning"},
             "annotations": {"summary": "Das letzte KIS-Backup ist älter als 15 Minuten (Lab-Wert). Wiederherstellungspunkt (RPO) wächst."}},
            {"alert": "KisDatenGesperrt", "expr": "lab_kis_locked == 1", "for": "0m",
             "labels": {"severity": "critical"},
             "annotations": {"summary": "KIS-Daten sind verschlüsselt oder gesperrt (Ransomware-Verdacht). Notbetrieb und Wiederherstellung einleiten."}},
            {"alert": "BackupNichtUnveraenderlich", "expr": "lab_backup_immutable_ratio < 1", "for": "1m",
             "labels": {"severity": "warning"},
             "annotations": {"summary": "Nicht alle Backups sind unveränderlich (WORM). Ein Angreifer könnte sie löschen."}},
            {"alert": "PolicyAbweichung", "expr": "lab_policy_mismatch > 0", "for": "2m",
             "labels": {"severity": "critical"},
             "annotations": {"summary": "Die Firewall verhält sich anders als die Policy in topology/klinikum.yml"}},
        ],
    }]
}

ALERTMANAGER = {
    "route": {"receiver": "portal", "group_by": ["alertname"], "group_wait": "5s", "group_interval": "30s", "repeat_interval": "1h"},
    "receivers": [{"name": "portal", "webhook_configs": [{"url": "http://localhost:8080/api/alert-webhook", "send_resolved": True}]}],
}

BLACKBOX = {"modules": {
    "tcp_connect": {"prober": "tcp", "timeout": "3s"},
    "icmp": {"prober": "icmp", "timeout": "3s", "icmp": {"preferred_ip_protocol": "ip4"}},
}}


def _panel(pid, title, ptype, x, y, w, h, targets, **extra):
    p = {"id": pid, "title": title, "type": ptype, "datasource": {"type": "prometheus", "uid": "prometheus"},
         "gridPos": {"x": x, "y": y, "w": w, "h": h}, "targets": targets}
    p.update(extra)
    return p


def render_dashboard(t: dict) -> dict:
    n_nodes = sum(1 for hc in t["hosts"].values() if hc.get("kind") != "hub")
    n_svc = sum(1 for hc in t["hosts"].values() for s in hc["services"] if s["kind"] in ("http", "tcp"))

    def tgt(expr, legend="", instant=False, fmt=None):
        d = {"expr": expr, "legendFormat": legend, "refId": "A", "instant": instant}
        if fmt:
            d["format"] = fmt
        return [d]

    def thresholds(*steps):
        return {"mode": "absolute", "steps": [{"color": c, "value": v} for c, v in steps]}

    stat_opts = {"reduceOptions": {"calcs": ["lastNotNull"]}, "colorMode": "background", "graphMode": "none"}
    panels = [
        _panel(1, f"Knoten erreichbar (von {n_nodes})", "stat", 0, 0, 6, 4, tgt('sum(up{job="lab-nodes"})', instant=True),
               options=stat_opts, fieldConfig={"defaults": {"thresholds": thresholds(("red", None), ("green", n_nodes))}, "overrides": []}),
        _panel(2, f"Dienste erreichbar (von {n_svc})", "stat", 6, 0, 6, 4, tgt('sum(probe_success{job="blackbox-tcp"})', instant=True),
               options=stat_opts, fieldConfig={"defaults": {"thresholds": thresholds(("red", None), ("green", n_svc))}, "overrides": []}),
        _panel(3, "Isolierte Zonen", "stat", 12, 0, 6, 4, tgt("sum(lab_fw_zone_isolated) or vector(0)", instant=True),
               options=stat_opts, fieldConfig={"defaults": {"thresholds": thresholds(("green", None), ("red", 1))}, "overrides": []}),
        _panel(4, "Abweichungen Policy gegen Firewall", "stat", 18, 0, 6, 4, tgt("max(lab_policy_mismatch) or vector(0)", instant=True),
               options=stat_opts, fieldConfig={"defaults": {"thresholds": thresholds(("green", None), ("red", 1))}, "overrides": []}),
        _panel(5, "Verworfene Pakete pro Sekunde (default-deny)", "timeseries", 0, 4, 12, 8,
               tgt('rate(lab_fw_rule_packets_total{rule="default-deny"}[1m])', "verworfen")),
        _panel(6, "Treffer pro Regel (Pakete pro Sekunde)", "timeseries", 12, 4, 12, 8,
               tgt("sum by (rule) (rate(lab_fw_rule_packets_total[1m]))", "{{rule}}")),
        _panel(7, "Antwortzeit der Dienste (Sekunden)", "timeseries", 0, 12, 12, 8,
               tgt('probe_duration_seconds{job="blackbox-tcp"}', "{{host}}:{{service}}")),
        _panel(8, "Offene Alarme", "table", 12, 12, 12, 8, tgt('ALERTS{alertstate="firing"}', instant=True, fmt="table")),
        _panel(9, "Dienste im Überblick (1 = erreichbar)", "table", 0, 20, 24, 10,
               tgt('probe_success{job="blackbox-tcp"}', instant=True, fmt="table"),
               transformations=[{"id": "organize", "options": {"excludeByName": {"Time": True, "__name__": True, "job": True, "instance": True}}}]),
        _panel(10, "Alter des letzten Backups (Sekunden)", "stat", 0, 30, 8, 4, tgt("max(lab_backup_age_seconds)", instant=True),
               options=stat_opts, fieldConfig={"defaults": {"unit": "s", "thresholds": thresholds(("green", None), ("orange", 600), ("red", 900))}, "overrides": []}),
        _panel(11, "KIS-Daten gesperrt (0 = normal)", "stat", 8, 30, 8, 4, tgt("max(lab_kis_locked) or vector(0)", instant=True),
               options=stat_opts, fieldConfig={"defaults": {"thresholds": thresholds(("green", None), ("red", 1))}, "overrides": []}),
        _panel(12, "Backups im Bestand und davon unveränderlich", "timeseries", 16, 30, 8, 4,
               tgt("lab_backup_count", "Backups") + [{"expr": "lab_backup_immutable_count", "legendFormat": "unveränderlich", "refId": "B", "instant": False}]),
    ]
    return {
        "uid": "klinikum-netz", "title": "Klinikum-Netz Übersicht", "schemaVersion": 39, "version": 1,
        "refresh": "15s", "time": {"from": "now-30m", "to": "now"}, "tags": ["klinikum", "netzwerk"],
        "panels": panels,
    }


def render_vpn_dashboard(t: dict) -> dict:
    n = len(t["vpn"]["peers"])
    ds = {"type": "prometheus", "uid": "prometheus"}

    def q(expr, legend="", fmt=None, instant=False):
        d = {"expr": expr, "legendFormat": legend, "refId": "A", "instant": instant}
        if fmt:
            d["format"] = fmt
        return [d]

    def th(*steps):
        return {"mode": "absolute", "steps": [{"color": c, "value": v} for c, v in steps]}

    stat = {"reduceOptions": {"calcs": ["lastNotNull"]}, "colorMode": "background", "graphMode": "none"}
    panels = [
        _panel(1, f"Verbundene Peers (von {n})", "stat", 0, 0, 6, 4, q("lab_vpn_peers_active", instant=True), options=stat,
               fieldConfig={"defaults": {"thresholds": th(("red", None), ("orange", 1), ("green", n))}, "overrides": []}),
        _panel(2, "Peers an unerwartetem Standort", "stat", 6, 0, 6, 4, q("sum(lab_vpn_peer_geo_unexpected)", instant=True), options=stat,
               fieldConfig={"defaults": {"thresholds": th(("green", None), ("red", 1))}, "overrides": []}),
        _panel(3, "Gateway abfragbar", "stat", 12, 0, 6, 4, q("lab_vpn_gateway_reachable", instant=True), options=stat,
               fieldConfig={"defaults": {"thresholds": th(("red", None), ("green", 1)),
                                         "mappings": [{"type": "value", "options": {"0": {"text": "nein"}, "1": {"text": "ja"}}}]}, "overrides": []}),
        _panel(4, "WireGuard-Exporter", "stat", 18, 0, 6, 4, q('up{job="wireguard"}', instant=True), options=stat,
               fieldConfig={"defaults": {"thresholds": th(("red", None), ("green", 1)),
                                         "mappings": [{"type": "value", "options": {"0": {"text": "aus"}, "1": {"text": "läuft"}}}]}, "overrides": []}),
        _panel(5, "Wer ist wo? (Karte)", "geomap", 0, 4, 12, 10, q("lab_vpn_peer_location", fmt="table", instant=True),
               options={"view": {"id": "coords", "lat": 49.0, "lon": 9.0, "zoom": 5},
                        "basemap": {"type": "default", "name": "Basemap"},
                        "layers": [{"type": "markers", "name": "Peers", "type": "markers",
                                    "location": {"mode": "coords", "latitude": "lat", "longitude": "lon"},
                                    "config": {"showLegend": False, "style": {"size": {"fixed": 10}, "color": {"fixed": "#0b5cab"}, "opacity": 0.9,
                                                                               "text": {"mode": "field", "field": "peer"}}}}],
                        "tooltip": {"mode": "details"}},
               transformations=[{"id": "convertFieldType", "options": {"conversions": [
                   {"targetField": "lat", "destinationType": "number"}, {"targetField": "lon", "destinationType": "number"}]}}]),
        _panel(6, "Letzter Handshake (Sekunden her)", "timeseries", 12, 4, 12, 10,
               q("time() - wireguard_latest_handshake_seconds", "{{friendly_name}} {{allowed_ips}}")),
        _panel(7, "Empfangen (Bytes pro Sekunde)", "timeseries", 0, 14, 12, 8,
               q("rate(wireguard_received_bytes_total[2m])", "{{friendly_name}} {{allowed_ips}}")),
        _panel(8, "Gesendet (Bytes pro Sekunde)", "timeseries", 12, 14, 12, 8,
               q("rate(wireguard_sent_bytes_total[2m])", "{{friendly_name}} {{allowed_ips}}")),
        _panel(9, "Peers (Nutzer, Gerät, Standort)", "table", 0, 22, 24, 8, q("lab_vpn_peer_up", fmt="table", instant=True),
               transformations=[{"id": "organize", "options": {"excludeByName": {"Time": True, "__name__": True, "job": True, "instance": True}}}]),
    ]
    return {"uid": "klinikum-vpn", "title": "Klinikum-VPN Live", "schemaVersion": 39, "version": 1, "refresh": "15s",
            "time": {"from": "now-30m", "to": "now"}, "tags": ["klinikum", "vpn"], "panels": panels}


# --------------------------------------------------------------------------
# VPN (WireGuard)
# --------------------------------------------------------------------------
def _keypair() -> dict:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    priv = X25519PrivateKey.generate()
    raw_priv = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    raw_pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"private": base64.b64encode(raw_priv).decode(), "public": base64.b64encode(raw_pub).decode()}


def render_vpn(t: dict, outdir: Path) -> dict[str, str]:
    vpn = t["vpn"]
    keyfile = outdir / "keys.json"
    keys = json.loads(keyfile.read_text()) if keyfile.exists() else {}
    for name in ["gateway", *vpn["peers"]]:
        keys.setdefault(name, _keypair())
    gw_ip = t["hosts"][vpn["gateway"]]["ip"]
    files = {"keys.json": json.dumps(keys, indent=2)}
    srv = [
        "# GENERIERT. Nur für das Lab, die Schlüssel sind nicht geheim.",
        "[Interface]",
        f"Address = {vpn['gateway_address']}/{T.ipaddress.ip_network(vpn['pool']).prefixlen}",
        f"ListenPort = {vpn['listen_port']}",
        f"PrivateKey = {keys['gateway']['private']}",
    ]
    for name, pc in vpn["peers"].items():
        srv += ["", f"# {name}: {pc['description']}", "[Peer]", f"# friendly_name = {name}", f"PublicKey = {keys[name]['public']}", f"AllowedIPs = {pc['address']}/32"]
        allowed = ", ".join(t["zones"][z]["cidr"] for z in pc["allowed_zones"])
        files[f"{name}.conf"] = "\n".join([
            f"# GENERIERT: {name}. {pc['description']}",
            "[Interface]", f"Address = {pc['address']}/32", f"PrivateKey = {keys[name]['private']}", "",
            "[Peer]", f"PublicKey = {keys['gateway']['public']}", f"Endpoint = {gw_ip}:{vpn['listen_port']}",
            f"AllowedIPs = {allowed}", "PersistentKeepalive = 15", ""])
    files["wg0.conf"] = "\n".join(srv) + "\n"
    return files


# --------------------------------------------------------------------------
def write(path: Path, text: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if mode:
        path.chmod(mode)


def dump_yaml(obj) -> str:
    return yaml.safe_dump(obj, sort_keys=False, allow_unicode=True, width=200)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--topology", default=str(ROOT / "topology" / "klinikum.yml"))
    ap.add_argument("--check", action="store_true", help="nur prüfen, nichts schreiben")
    args = ap.parse_args()

    try:
        t = T.load(args.topology)
    except T.TopologyError as exc:
        print(f"FEHLER in der Topologie:\n{exc}", file=sys.stderr)
        return 2
    problems = T.check_assertions(t)
    if problems:
        print("FEHLER: Die Policy widerspricht den Sicherheitsaussagen:", file=sys.stderr)
        for p in problems:
            print(f" - {p}", file=sys.stderr)
        return 3
    rules = T.expand_rules(t)
    matrix = T.expected_matrix(t)
    print(f"Topologie ok: {len(t['zones'])} Zonen, {len(t['hosts'])} Hosts, {len(t['policy'])} Policy-Einträge, "
          f"{len(rules)} Regeln, {len(matrix)} Testfälle, {len(t.get('assertions', []))} Sicherheitsaussagen")
    if args.check:
        return 0

    write(BUILD / "fw" / "nftables.conf", render_nft(t))
    policy = {
        "zones": {z: {"cidr": zc["cidr"], "title": zc["title"]} for z, zc in t["zones"].items()},
        "rules": [{**r, "ports": r["ports"]} for r in rules],
        "names": {p["id"]: p["name"] for p in t["policy"]},
        "matrix": matrix,
    }
    write(BUILD / "policy.json", json.dumps(policy, indent=2, ensure_ascii=False))
    write(ROOT / "docker-compose.yml", "# GENERIERT von tools/render.py. Nicht von Hand ändern.\n" + dump_yaml(render_compose(t)))
    pdir = BUILD / "prometheus"
    write(pdir / "prometheus.yml", dump_yaml(render_prometheus(t)))
    write(pdir / "alerts.yml", dump_yaml(ALERTS))
    write(pdir / "alertmanager.yml", dump_yaml(ALERTMANAGER))
    write(pdir / "blackbox.yml", dump_yaml(BLACKBOX))
    gdir = BUILD / "grafana" / "provisioning"
    write(gdir / "datasources" / "prometheus.yml", dump_yaml({"apiVersion": 1, "datasources": [
        {"name": "Prometheus", "uid": "prometheus", "type": "prometheus", "access": "proxy", "url": "http://localhost:9090", "isDefault": True}]}))
    write(gdir / "dashboards" / "dashboards.yml", dump_yaml({"apiVersion": 1, "providers": [
        {"name": "klinikum", "type": "file", "options": {"path": "/etc/grafana/provisioning/dashboards"}}]}))
    write(gdir / "dashboards" / "klinikum.json", json.dumps(render_dashboard(t), indent=2, ensure_ascii=False))
    write(gdir / "dashboards" / "klinikum-vpn.json", json.dumps(render_vpn_dashboard(t), indent=2, ensure_ascii=False))
    for fname, text in render_vpn(t, BUILD / "vpn").items():
        write(BUILD / "vpn" / fname, text, 0o600)
    print("Geschrieben: build/, docker-compose.yml")
    return 0


if __name__ == "__main__":
    sys.exit(main())
