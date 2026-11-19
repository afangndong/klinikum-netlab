"""Topologie laden, prüfen und die Firewall-Policy auswerten.

Alles, was das Lab über das Netzwerk weiß, steht in topology/klinikum.yml.
Dieses Modul ist die einzige Stelle, die diese Datei interpretiert. Der
Generator, die Tests und das Portal benutzen dieselbe Logik.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Iterable

import jsonschema
import yaml

PORT_RE = re.compile(r"^(?:(tcp|udp)/(\d{1,5})|icmp)$")


class TopologyError(Exception):
    """Die Topologie ist ungültig. Die Nachricht nennt alle Fehler."""


SCHEMA = {
    "type": "object",
    "required": ["name", "supernet", "firewall", "agent_port", "zones", "hosts", "vpn", "policy"],
    "properties": {
        "zones": {
            "type": "object",
            "additionalProperties": {
                "type": "object",
                "required": ["vlan", "cidr", "title"],
                "properties": {
                    "vlan": {"type": "integer", "minimum": 1, "maximum": 4094},
                    "cidr": {"type": "string"},
                    "title": {"type": "string"},
                },
            },
        },
        "hosts": {
            "type": "object",
            "additionalProperties": {
                "type": "object",
                "required": ["zone", "ip", "title", "services"],
                "properties": {
                    "services": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["name", "port", "kind", "title"],
                            "properties": {
                                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                                "kind": {"enum": ["http", "tcp", "udp"]},
                            },
                        },
                    }
                },
            },
        },
        "policy": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "name", "from", "to", "ports"],
                "properties": {"ports": {"type": "array", "items": {"type": "string"}, "minItems": 1}},
            },
        },
    },
}


# --------------------------------------------------------------------------
# Laden und prüfen
# --------------------------------------------------------------------------
def load(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        topo = yaml.safe_load(fh)
    validate(topo)
    return topo


def validate(t: dict) -> None:
    errors: list[str] = []
    try:
        jsonschema.validate(t, SCHEMA)
    except jsonschema.ValidationError as exc:
        raise TopologyError(f"Schema: {exc.message} (bei {'/'.join(map(str, exc.absolute_path))})") from exc

    supernet = ipaddress.ip_network(t["supernet"])
    nets = {}
    for z, zc in t["zones"].items():
        net = ipaddress.ip_network(zc["cidr"])
        nets[z] = net
        if not net.subnet_of(supernet):
            errors.append(f"Zone {z}: {net} liegt nicht im Supernet {supernet}")
    vlans = [zc["vlan"] for zc in t["zones"].values()]
    if len(vlans) != len(set(vlans)):
        errors.append("VLAN-IDs sind nicht eindeutig")
    for a in nets:
        for b in nets:
            if a < b and nets[a].overlaps(nets[b]):
                errors.append(f"Zonen {a} und {b} überlappen")

    seen_ip: dict[str, str] = {}
    for h, hc in t["hosts"].items():
        if hc["zone"] not in t["zones"]:
            errors.append(f"Host {h}: unbekannte Zone {hc['zone']}")
            continue
        ip = ipaddress.ip_address(hc["ip"])
        net = nets[hc["zone"]]
        if ip not in net:
            errors.append(f"Host {h}: {ip} liegt nicht in {net}")
        elif int(ip) - int(net.network_address) in (t["firewall"]["host_octet"], 254, 0, 255):
            errors.append(f"Host {h}: {ip} ist reserviert (Firewall/Gateway)")
        if hc["ip"] in seen_ip:
            errors.append(f"IP {hc['ip']} doppelt: {h} und {seen_ip[hc['ip']]}")
        seen_ip[hc["ip"]] = h
        ports = set()
        for s in hc["services"]:
            key = (s["kind"] == "udp", s["port"])
            if key in ports:
                errors.append(f"Host {h}: Port {s['port']} doppelt")
            ports.add(key)

    pool = ipaddress.ip_network(t["vpn"]["pool"])
    seen_peer_ip: dict[str, str] = {}
    for pname, pc in t["vpn"]["peers"].items():
        if pc["address"] in seen_peer_ip:
            errors.append(f"VPN-Adresse {pc['address']} doppelt: {pname} und {seen_peer_ip[pc['address']]}")
        seen_peer_ip[pc["address"]] = pname
    if t["vpn"]["gateway"] not in t["hosts"]:
        errors.append("vpn.gateway ist kein Host")
    for pname, pc in t["vpn"]["peers"].items():
        if ipaddress.ip_address(pc["address"]) not in pool:
            errors.append(f"VPN-Peer {pname}: Adresse außerhalb des Pools")
        for z in pc["allowed_zones"]:
            if z not in t["zones"]:
                errors.append(f"VPN-Peer {pname}: unbekannte Zone {z}")
        loc = pc.get("location")
        if not loc or not (-90 <= loc.get("lat", 999) <= 90 and -180 <= loc.get("lon", 999) <= 180):
            errors.append(f"VPN-Peer {pname}: location mit gültigem lat/lon fehlt")
        if not pc.get("expected_countries"):
            errors.append(f"VPN-Peer {pname}: expected_countries fehlt (Alarm bei unerwartetem Land)")
        if not any(hc.get("vpn_peer") == pname for hc in t["hosts"].values()):
            errors.append(f"VPN-Peer {pname}: kein Host (Client) verweist darauf")
    for h, hc in t["hosts"].items():
        if "vpn_peer" in hc and hc["vpn_peer"] not in t["vpn"]["peers"]:
            errors.append(f"Host {h}: unbekannter VPN-Peer {hc['vpn_peer']}")

    ids = [p["id"] for p in t["policy"]]
    if len(ids) != len(set(ids)):
        errors.append("Policy-IDs sind nicht eindeutig")
    for p in t["policy"]:
        for side in ("from", "to"):
            try:
                selector_cidrs(t, p[side])
            except TopologyError as exc:
                errors.append(f"Policy {p['id']} ({side}): {exc}")
        for port in p["ports"]:
            if not PORT_RE.match(port):
                errors.append(f"Policy {p['id']}: ungültiger Port '{port}'")
            elif port != "icmp" and not 1 <= int(port.split("/")[1]) <= 65535:
                errors.append(f"Policy {p['id']}: Port außerhalb des Bereichs '{port}'")
    if errors:
        raise TopologyError("\n".join(f" - {e}" for e in errors))


# --------------------------------------------------------------------------
# Selektoren und Regeln
# --------------------------------------------------------------------------
def selector_cidrs(t: dict, sel: dict) -> list[str]:
    """Wandelt einen Selektor in eine Liste von CIDRs um."""
    if "zone" in sel:
        if sel["zone"] == "*":
            return [t["supernet"]]
        if sel["zone"] not in t["zones"]:
            raise TopologyError(f"unbekannte Zone '{sel['zone']}'")
        return [t["zones"][sel["zone"]]["cidr"]]
    if "host" in sel:
        return [host_cidr(t, sel["host"])]
    if "hosts" in sel:
        return [host_cidr(t, h) for h in sel["hosts"]]
    if "vpn_peer" in sel:
        peer = t["vpn"]["peers"].get(sel["vpn_peer"])
        if peer is None:
            raise TopologyError(f"unbekannter VPN-Peer '{sel['vpn_peer']}'")
        return [f"{peer['address']}/32"]
    raise TopologyError(f"unbekannter Selektor {sel}")


def host_cidr(t: dict, host: str) -> str:
    if host not in t["hosts"]:
        raise TopologyError(f"unbekannter Host '{host}'")
    return f"{t['hosts'][host]['ip']}/32"


def selector_hosts(t: dict, sel: dict) -> list[str]:
    """Hosts, die ein Selektor trifft (für Tests und Assertions)."""
    if "zone" in sel:
        if sel["zone"] == "*":
            return list(t["hosts"])
        return [h for h, hc in t["hosts"].items() if hc["zone"] == sel["zone"]]
    if "host" in sel:
        return [sel["host"]]
    if "hosts" in sel:
        return list(sel["hosts"])
    if "vpn_peer" in sel:
        return [h for h, hc in t["hosts"].items() if hc.get("vpn_peer") == sel["vpn_peer"]]
    return []


def _in(ip: str, cidrs: Iterable[str]) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in ipaddress.ip_network(c) for c in cidrs)


def expand_rules(t: dict) -> list[dict]:
    """Policy -> flache Regelliste. Jede Regel hat genau ein Protokoll."""
    rules = []
    for p in t["policy"]:
        src = selector_cidrs(t, p["from"])
        dst = selector_cidrs(t, p["to"])
        tcp = sorted({int(x.split("/")[1]) for x in p["ports"] if x.startswith("tcp/")})
        udp = sorted({int(x.split("/")[1]) for x in p["ports"] if x.startswith("udp/")})
        base = {"id": p["id"], "name": p["name"], "src": src, "dst": dst}
        if tcp:
            rules.append({**base, "proto": "tcp", "ports": tcp})
        if udp:
            rules.append({**base, "proto": "udp", "ports": udp})
        if "icmp" in p["ports"]:
            rules.append({**base, "proto": "icmp", "ports": []})
    return rules


def source_ip(t: dict, src: str, dst: str) -> str:
    """Welche Quell-IP sieht die Firewall, wenn src zu dst verbindet?

    VPN-Clients nutzen für freigegebene Zonen die Tunneladresse, sonst ihre
    normale Adresse (die Firewall verwirft sie dann).
    """
    sh, dh = t["hosts"][src], t["hosts"][dst]
    peer = sh.get("vpn_peer")
    if peer and dh["zone"] in t["vpn"]["peers"][peer]["allowed_zones"]:
        return t["vpn"]["peers"][peer]["address"]
    return sh["ip"]


def is_allowed(t: dict, src: str, dst: str, proto: str, port: int | None, rules: list[dict] | None = None) -> tuple[bool, str | None]:
    rules = rules if rules is not None else expand_rules(t)
    sip = source_ip(t, src, dst)
    dip = t["hosts"][dst]["ip"]
    for r in rules:
        if r["proto"] != proto:
            continue
        if proto != "icmp" and port not in r["ports"]:
            continue
        if _in(sip, r["src"]) and _in(dip, r["dst"]):
            return True, r["id"]
    return False, None


def expected_matrix(t: dict) -> list[dict]:
    """Alle TCP-Dienste zwischen verschiedenen Zonen mit erwartetem Ergebnis."""
    rules = expand_rules(t)
    out = []
    for s, sh in t["hosts"].items():
        for d, dh in t["hosts"].items():
            if sh["zone"] == dh["zone"]:
                continue  # gleiche Zone = gleiches VLAN, die Firewall sieht es nicht
            for svc in dh["services"]:
                if svc["kind"] not in ("http", "tcp"):
                    continue
                ok, pid = is_allowed(t, s, d, "tcp", svc["port"], rules)
                out.append({
                    "src": s, "dst": d, "port": svc["port"], "service": svc["name"],
                    "expected": "allow" if ok else "deny", "policy": pid,
                })
    return out


def check_assertions(t: dict) -> list[str]:
    """Prüft die handgeschriebenen Sicherheitsaussagen gegen die Policy."""
    rules = expand_rules(t)
    problems = []
    for a in t.get("assertions", []):
        proto, port = a["port"].split("/")
        port = int(port)
        checked = 0
        for s in selector_hosts(t, a["from"]):
            for d in selector_hosts(t, a["to"]):
                if t["hosts"][s]["zone"] == t["hosts"][d]["zone"]:
                    continue
                if not any(sv["port"] == port and sv["kind"] != "udp" for sv in t["hosts"][d]["services"]):
                    continue
                checked += 1
                ok, pid = is_allowed(t, s, d, proto, port, rules)
                got = "allow" if ok else "deny"
                if got != a["expect"]:
                    problems.append(f"{s} -> {d}:{a['port']} soll {a['expect']} sein, ist {got} ({pid}). Grund der Aussage: {a['why']}")
        if checked == 0:
            problems.append(f"Aussage trifft keinen Dienst: {a['from']} -> {a['to']} {a['port']}")
    return problems


def zone_of_ip(t: dict, ip: str) -> str | None:
    for z, zc in t["zones"].items():
        if ipaddress.ip_address(ip) in ipaddress.ip_network(zc["cidr"]):
            return z
    return None


def zone_gateway(t: dict, zone: str) -> str:
    net = ipaddress.ip_network(t["zones"][zone]["cidr"])
    return str(net.network_address + t["firewall"]["host_octet"])
