"""Firewall-Agent: liest Regelzähler aus nftables und steuert die Notfall-Isolation.

Läuft im Firewall-Container. Erreichbar nur aus der Zone mgmt (siehe nftables.conf).
  GET  /rules                 Regeln mit Trefferzählern
  GET  /zones                 Zonen und ob sie isoliert sind
  POST /isolate/{zone}        Zone abschneiden (Header X-Lab-Token nötig)
  POST /release/{zone}        Isolation aufheben
  GET  /metrics               Prometheus-Metriken
"""
from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import time

import uvicorn
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse

POLICY = json.load(open(os.environ.get("POLICY_FILE", "/config/policy.json"), encoding="utf-8"))
TOKEN = os.environ.get("LAB_TOKEN", "klinikum-lab")
NFT = os.environ.get("NFT_BIN", "nft")
BIND = os.environ.get("FW_BIND", "0.0.0.0")
PORT = int(os.environ.get("FW_PORT", "9000"))
ZONES = POLICY["zones"]
EVENTS: list[dict] = []

app = FastAPI(title="fw-agent", docs_url=None, redoc_url=None)


def nft_json(*args: str) -> dict:
    out = subprocess.run([NFT, "-j", *args], capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def rule_counters() -> list[dict]:
    rules = []
    for item in nft_json("list", "chain", "ip", "klinikum", "forward")["nftables"]:
        r = item.get("rule")
        if not r:
            continue
        counter = next((e["counter"] for e in r["expr"] if "counter" in e), {"packets": 0, "bytes": 0})
        rules.append({"handle": r["handle"], "id": r.get("comment", ""), "packets": counter["packets"], "bytes": counter["bytes"]})
    return rules


def isolated_cidrs() -> set[str]:
    data = nft_json("list", "set", "ip", "klinikum", "isolated")["nftables"]
    cidrs: set[str] = set()
    for item in data:
        for elem in item.get("set", {}).get("elem", []) or []:
            pre = elem.get("prefix") if isinstance(elem, dict) else None
            if pre:
                cidrs.add(f"{pre['addr']}/{pre['len']}")
            elif isinstance(elem, str):
                cidrs.add(elem)
    return cidrs


def zone_state() -> dict[str, bool]:
    iso = isolated_cidrs()
    return {z: zc["cidr"] in iso for z, zc in ZONES.items()}


@app.get("/rules")
def rules():
    names = POLICY["names"]
    rows = []
    for rc in rule_counters():
        rid = rc["id"]
        rows.append({**rc, "name": names.get(rid, {"default-deny": "Alles andere verwerfen", "ISOLATED": "Notfall-Isolation"}.get(rid, rid))})
    return {"rules": rows, "defined": POLICY["rules"]}


@app.get("/zones")
def zones():
    state = zone_state()
    return {"zones": {z: {"cidr": zc["cidr"], "title": zc["title"], "isolated": state[z]} for z, zc in ZONES.items()},
            "events": EVENTS[-20:]}


def _change(zone: str, action: str, token: str | None) -> dict:
    if token != TOKEN:
        raise HTTPException(401, "X-Lab-Token fehlt oder ist falsch")
    if zone not in ZONES:
        raise HTTPException(404, "unbekannte Zone")
    if zone == "mgmt":
        raise HTTPException(409, "Die Zone mgmt wird nicht isoliert, sonst verliert man die Kontrolle")
    cidr = ZONES[zone]["cidr"]
    subprocess.run([NFT, action, "element", "ip", "klinikum", "isolated", "{ " + cidr + " }"], check=True, capture_output=True)
    EVENTS.append({"t": time.strftime("%H:%M:%S"), "zone": zone, "action": "isoliert" if action == "add" else "freigegeben"})
    return {"zone": zone, "isolated": action == "add"}


@app.post("/isolate/{zone}")
def isolate(zone: str, x_lab_token: str | None = Header(default=None)):
    return _change(zone, "add", x_lab_token)


@app.post("/release/{zone}")
def release(zone: str, x_lab_token: str | None = Header(default=None)):
    return _change(zone, "delete", x_lab_token)


@app.get("/metrics", response_class=PlainTextResponse)
def metrics():
    lines = ["# TYPE lab_fw_rule_packets_total counter", "# TYPE lab_fw_rule_bytes_total counter"]
    agg: dict[str, list[int]] = {}
    for rc in rule_counters():
        a = agg.setdefault(rc["id"], [0, 0])
        a[0] += rc["packets"]
        a[1] += rc["bytes"]
    for rid, (p, b) in agg.items():
        lines.append(f'lab_fw_rule_packets_total{{rule="{rid}"}} {p}')
        lines.append(f'lab_fw_rule_bytes_total{{rule="{rid}"}} {b}')
    lines.append("# TYPE lab_fw_zone_isolated gauge")
    for z, s in zone_state().items():
        lines.append(f'lab_fw_zone_isolated{{zone="{z}"}} {int(s)}')
    return "\n".join(lines) + "\n"


@app.get("/health")
def health():
    return {"status": "ok", "rules": len(rule_counters())}


if __name__ == "__main__":
    uvicorn.run(app, host=BIND, port=PORT, log_level="warning")
