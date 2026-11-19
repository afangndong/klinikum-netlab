"""VPN-Live: Zustand der WireGuard-Peers, Standort, Alarme.

Quelle: Agent des VPN-Gateways (/wg, entspricht `wg show wg0 dump`).
Zuordnung Peer -> Name über die Tunneladresse (AllowedIPs des Peers), nicht über Schlüssel.
Standort: 1. manuelle Simulation, 2. optional GeoIP (MaxMind-Datei, nur bei öffentlicher Quell-IP),
3. simulierter Standort aus der Topologie (im Lab sind alle Quell-IPs privat).
"""
from __future__ import annotations

import ipaddress
import os
import threading
import time

import requests

ACTIVE_SECONDS = int(os.environ.get("VPN_ACTIVE_SECONDS", "180"))
GEO_DB = os.environ.get("GEOIP_DB", "/geo/GeoLite2-City.mmdb")
PRESETS = {
    "berlin": {"city": "Berlin", "country": "DE", "lat": 52.52, "lon": 13.40},
    "sao-paulo": {"city": "São Paulo", "country": "BR", "lat": -23.55, "lon": -46.63},
    "lagos": {"city": "Lagos", "country": "NG", "lat": 6.52, "lon": 3.38},
    "singapur": {"city": "Singapur", "country": "SG", "lat": 1.35, "lon": 103.82},
}

_override: dict[str, dict] = {}
_lock = threading.Lock()
_cache: dict = {"ts": 0.0, "data": None}


def _geoip(ip: str) -> dict | None:
    """Optional. Braucht `pip install geoip2` und die GeoLite2-City-Datei. Im Lab nicht getestet."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or not os.path.exists(GEO_DB):
            return None
        import geoip2.database  # type: ignore

        with geoip2.database.Reader(GEO_DB) as rd:
            r = rd.city(ip)
            return {"city": r.city.name or "?", "country": r.country.iso_code or "?",
                    "lat": r.location.latitude, "lon": r.location.longitude}
    except Exception:
        return None


def simulate(peer: str, preset: str | None, topo: dict) -> dict:
    if peer not in topo["vpn"]["peers"]:
        raise KeyError(peer)
    with _lock:
        if preset in (None, "", "reset"):
            _override.pop(peer, None)
        elif preset in PRESETS:
            _override[peer] = PRESETS[preset]
        else:
            raise ValueError(preset)
        _cache["ts"] = 0
    return {"peer": peer, "override": _override.get(peer)}


def build_state(topo: dict, wg: dict | None, now: float | None = None) -> dict:
    now = now or time.time()
    by_addr = {pc["address"]: n for n, pc in topo["vpn"]["peers"].items()}
    live: dict[str, dict] = {}
    if wg:
        for p in wg["peers"]:
            for cidr in p["allowed_ips"]:
                name = by_addr.get(cidr.split("/")[0])
                if name:
                    live[name] = p
    peers = []
    for name, pc in topo["vpn"]["peers"].items():
        p = live.get(name)
        age = None if not p or not p["latest_handshake"] else max(0, int(now - p["latest_handshake"]))
        endpoint_ip = p["endpoint"].rsplit(":", 1)[0].strip("[]") if p and p["endpoint"] else None
        with _lock:
            ov = _override.get(name)
        loc, source = pc["location"], "simuliert (Topologie)"
        if ov:
            loc, source = ov, "simuliert (Reise)"
        elif endpoint_ip and (g := _geoip(endpoint_ip)):
            loc, source = g, "GeoIP"
        up = age is not None and age <= ACTIVE_SECONDS
        peers.append({
            "peer": name, "user": pc["user"], "device": pc["device"], "address": pc["address"],
            "allowed_zones": pc["allowed_zones"], "description": pc["description"],
            "up": up, "handshake_age_s": age, "endpoint": p["endpoint"] if p else None,
            "rx_bytes": p["rx_bytes"] if p else 0, "tx_bytes": p["tx_bytes"] if p else 0,
            "location": {**loc, "source": source},
            "expected_countries": pc["expected_countries"],
            "geo_unexpected": loc["country"] not in pc["expected_countries"],
            "known_to_gateway": p is not None,
        })
    return {"ts": now, "gateway": {"name": topo["vpn"]["gateway"], "location": topo["vpn"]["gateway_location"],
                                   "reachable": wg is not None},
            "peers": peers, "active": sum(1 for x in peers if x["up"]),
            "unexpected": sum(1 for x in peers if x["geo_unexpected"])}


def fetch(topo: dict, agent_port: int, ttl: float = 5.0) -> dict:
    with _lock:
        if _cache["data"] is not None and time.time() - _cache["ts"] < ttl:
            return _cache["data"]
    gw_ip = topo["hosts"][topo["vpn"]["gateway"]]["ip"]
    try:
        r = requests.get(f"http://{gw_ip}:{agent_port}/wg", timeout=2)
        r.raise_for_status()
        wg = r.json()
    except requests.RequestException:
        wg = None
    data = build_state(topo, wg)
    with _lock:
        _cache.update(ts=time.time(), data=data)
    return data


def metrics_lines(state: dict) -> list[str]:
    out = [
        "# TYPE lab_vpn_gateway_reachable gauge", f"lab_vpn_gateway_reachable {int(state['gateway']['reachable'])}",
        "# TYPE lab_vpn_peers_active gauge", f"lab_vpn_peers_active {state['active']}",
        "# TYPE lab_vpn_peer_up gauge", "# TYPE lab_vpn_peer_handshake_age_seconds gauge",
        "# TYPE lab_vpn_peer_geo_unexpected gauge", "# TYPE lab_vpn_peer_location gauge",
    ]
    for p in state["peers"]:
        lab = f'peer="{p["peer"]}",device="{p["device"]}"'
        out.append(f"lab_vpn_peer_up{{{lab}}} {int(p['up'])}")
        if p["handshake_age_s"] is not None:
            out.append(f"lab_vpn_peer_handshake_age_seconds{{{lab}}} {p['handshake_age_s']}")
        out.append(f"lab_vpn_peer_geo_unexpected{{{lab},country=\"{p['location']['country']}\"}} {int(p['geo_unexpected'])}")
        loc = p["location"]
        out.append(f'lab_vpn_peer_location{{{lab},city="{loc["city"]}",country="{loc["country"]}",lat="{loc["lat"]}",lon="{loc["lon"]}"}} 1')
    return out
