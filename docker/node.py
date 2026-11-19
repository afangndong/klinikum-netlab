"""Knoten im Klinikum-Lab (Server, Arbeitsplatz, Medizingerät, ...).

Ein Knoten macht drei Dinge:
  1. Er bietet seine Dienste an (HTTP-Seite oder TCP-Banner), mit synthetischen Daten.
  2. Er hat einen Messpunkt (Agent) auf AGENT_PORT: /health, /metrics, /probe.
  3. Er kann von seinem Standort aus Verbindungen testen. Damit prüft das Portal,
     was die Firewall wirklich durchlässt (Sicht aus jeder Zone).

Konfiguration über Umgebungsvariablen (siehe docker-compose.yml).
"""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

NAME = os.environ.get("NODE_NAME", "node")
ZONE = os.environ.get("NODE_ZONE", "?")
IP = os.environ.get("NODE_IP", "")
BIND = os.environ.get("NODE_BIND", "0.0.0.0")
TITLE = os.environ.get("NODE_TITLE", NAME)
DESCRIPTION = os.environ.get("NODE_DESCRIPTION", "")
AGENT_PORT = int(os.environ.get("AGENT_PORT", "7070"))
ROLE = os.environ.get("ROLE", "node")
SERVICES = json.loads(os.environ.get("NODE_SERVICES", "[]"))
SUPERNET = ipaddress.ip_network(os.environ.get("SUPERNET", "10.10.0.0/16"))
STARTED = time.time()

# Synthetische Daten. Es sind keine echten Personen.
DATA = {
    "kis": {"patienten": [
        {"id": "P-1001", "name": "Erika Beispiel", "station": "3B", "aufnahme": "2026-11-10"},
        {"id": "P-1002", "name": "Max Mustermann", "station": "2A", "aufnahme": "2026-11-12"},
        {"id": "P-1003", "name": "Lena Testfall", "station": "ITS", "aufnahme": "2026-11-15"},
    ]},
    "pacs": {"studien": [
        {"id": "S-501", "modalitaet": "MR", "region": "Knie", "patient": "P-1001"},
        {"id": "S-502", "modalitaet": "CT", "region": "Thorax", "patient": "P-1003"},
    ]},
    "lis": {"auftraege": [
        {"id": "L-77", "analyse": "Blutbild", "status": "fertig", "patient": "P-1002"},
        {"id": "L-78", "analyse": "CRP", "status": "in Arbeit", "patient": "P-1003"},
    ]},
    "device": {"status": "betriebsbereit", "firmware": "7.4.1-lab", "letzte_wartung": "2026-09-30"},
    "generic": {"info": "Beispielseite"},
}

counters = {"probes_ok": 0, "probes_failed": 0, "service_requests": 0}
lock = threading.Lock()


# --------------------------------------------------------------------------
# Dienste
# --------------------------------------------------------------------------
class ServiceHandler(BaseHTTPRequestHandler):
    svc: dict = {}

    def log_message(self, *args):  # still
        pass

    def do_GET(self):
        with lock:
            counters["service_requests"] += 1
        data = DATA.get(self.svc.get("data", ""), None)
        if self.path.startswith("/api") and data is not None:
            body = json.dumps({"host": NAME, "zone": ZONE, **data}, ensure_ascii=False).encode()
            ctype = "application/json; charset=utf-8"
        else:
            keys = ", ".join(data) if data else ""
            body = (
                f"<!doctype html><meta charset=utf-8><title>{self.svc['title']}</title>"
                f"<body style='font-family:sans-serif;max-width:40rem;margin:3rem auto'>"
                f"<h1>{self.svc['title']}</h1><p>Host <b>{NAME}</b> in Zone <b>{ZONE}</b> ({IP}).</p>"
                f"<p>{DESCRIPTION}</p><p>Synthetische Daten (Lab): <code>/api</code> {keys}</p>"
            ).encode()
            ctype = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_http(svc: dict) -> None:
    handler = type(f"H{svc['port']}", (ServiceHandler,), {"svc": svc})
    srv = ThreadingHTTPServer((BIND, svc["port"]), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def start_tcp(svc: dict) -> None:
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((BIND, svc["port"]))
    sock.listen(32)
    banner = f"{svc['name'].upper()} {NAME} (Lab-Simulation)\r\n".encode()

    def loop():
        while True:
            conn, _ = sock.accept()
            with lock:
                counters["service_requests"] += 1
            try:
                conn.sendall(banner)
            except OSError:
                pass
            finally:
                conn.close()

    threading.Thread(target=loop, daemon=True).start()


def start_services() -> None:
    for svc in SERVICES:
        try:
            if svc["kind"] == "http":
                start_http(svc)
            elif svc["kind"] == "tcp":
                start_tcp(svc)
            # udp: wird vom VPN-Gateway selbst bedient (WireGuard)
        except OSError as exc:
            print(f"Dienst {svc['name']} auf {svc['port']} nicht gestartet: {exc}", flush=True)


# --------------------------------------------------------------------------
# Messpunkt (Agent)
# --------------------------------------------------------------------------
app = FastAPI(title=f"agent {NAME}", docs_url=None, redoc_url=None)


class Target(BaseModel):
    host: str
    port: int


class Batch(BaseModel):
    targets: list[Target]


def probe(host: str, port: int, timeout: float = 0.8) -> dict:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError as exc:
        raise HTTPException(400, "host muss eine IP-Adresse sein") from exc
    if addr not in SUPERNET:
        raise HTTPException(400, "Ziel liegt außerhalb des Lab-Netzes")  # kein Missbrauch als Scanner nach außen
    if not 1 <= port <= 65535:
        raise HTTPException(400, "ungültiger Port")
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            ok, err = True, None
    except OSError as exc:
        ok, err = False, type(exc).__name__
    ms = round((time.perf_counter() - t0) * 1000, 1)
    with lock:
        counters["probes_ok" if ok else "probes_failed"] += 1
    return {"host": host, "port": port, "ok": ok, "ms": ms, "error": err}


@app.get("/health")
def health():
    return {"name": NAME, "zone": ZONE, "ip": IP, "role": ROLE, "title": TITLE,
            "uptime_s": round(time.time() - STARTED), "services": SERVICES}


@app.get("/probe")
def probe_one(host: str, port: int):
    return probe(host, port)


@app.post("/probe-batch")
def probe_batch(batch: Batch):
    if len(batch.targets) > 200:
        raise HTTPException(400, "zu viele Ziele")
    with ThreadPoolExecutor(max_workers=24) as pool:
        return list(pool.map(lambda t: probe(t.host, t.port), batch.targets))


def wg_dump() -> dict:
    """Liest den WireGuard-Zustand (nur auf dem VPN-Gateway). Der private Schlüssel wird nie ausgegeben."""
    wg = os.environ.get("WG_BIN", "wg")
    if ROLE != "vpn-gateway":
        raise HTTPException(404, "kein VPN-Gateway")
    if shutil.which(wg) is None:
        raise HTTPException(503, "wg nicht installiert")
    cp = subprocess.run([wg, "show", "wg0", "dump"], capture_output=True, text=True, timeout=5)
    if cp.returncode != 0:
        raise HTTPException(503, "wg0 nicht aktiv: " + cp.stderr.strip()[:120])
    lines = cp.stdout.strip().splitlines()
    iface = lines[0].split("\t")
    peers = []
    for ln in lines[1:]:
        f = ln.split("\t")
        if len(f) < 8:
            continue
        peers.append({"public_key": f[0], "endpoint": None if f[2] == "(none)" else f[2], "allowed_ips": f[3].split(","),
                      "latest_handshake": int(f[4]), "rx_bytes": int(f[5]), "tx_bytes": int(f[6]),
                      "keepalive": None if f[7] == "off" else int(f[7])})
    return {"interface": "wg0", "public_key": iface[1], "listen_port": int(iface[2]), "now": int(time.time()), "peers": peers}


@app.get("/wg")
def wg_state():
    return wg_dump()


@app.get("/metrics", response_class=PlainTextResponse)
def metrics():
    lab = f'host="{NAME}",zone="{ZONE}"'
    with lock:
        c = dict(counters)
    return (
        "# TYPE lab_node_uptime_seconds gauge\n"
        f"lab_node_uptime_seconds{{{lab}}} {time.time() - STARTED:.0f}\n"
        "# TYPE lab_node_probes_total counter\n"
        f'lab_node_probes_total{{{lab},result="ok"}} {c["probes_ok"]}\n'
        f'lab_node_probes_total{{{lab},result="failed"}} {c["probes_failed"]}\n'
        "# TYPE lab_node_service_requests_total counter\n"
        f"lab_node_service_requests_total{{{lab}}} {c['service_requests']}\n"
    )


if __name__ == "__main__":
    start_services()
    uvicorn.run(app, host=BIND, port=AGENT_PORT, log_level="warning")
