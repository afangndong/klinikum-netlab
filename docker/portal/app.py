"""NetOps-Portal für das Klinikum-Lab.

Zeigt Zonen, Hosts, Firewall-Regeln mit Trefferzählern, die Erreichbarkeitsmatrix
(Soll gegen Ist), VPN-Peers und Alarme. Über das Portal kann man eine Zone im
Notfall isolieren.

Das Portal ist Teil des Labs. Es hat bewusst keine Anmeldung. Nicht ins Internet stellen.
"""
from __future__ import annotations

import base64
import html
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import jinja2
import requests
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from starlette.concurrency import run_in_threadpool
from fastapi.staticfiles import StaticFiles

from netlab import topology as T
from portal import vpnlive

HERE = Path(__file__).resolve().parent
TOPO_PATH = os.environ.get("TOPOLOGY", "/config/topology/klinikum.yml")
FW_URL = os.environ.get("FW_URL", "http://10.10.10.1:9000")
LAB_TOKEN = os.environ.get("LAB_TOKEN", "klinikum-lab")
AM_URL = os.environ.get("ALERTMANAGER_URL", "http://localhost:9093")
GRAFANA_URL = os.environ.get("GRAFANA_PUBLIC_URL", "http://localhost:3000")
PROM_URL = os.environ.get("PROMETHEUS_PUBLIC_URL", "http://localhost:9090")
MATRIX_INTERVAL = int(os.environ.get("MATRIX_INTERVAL", "120"))
BACKGROUND = os.environ.get("MATRIX_BACKGROUND", "1") == "1"
BIND_IP = os.environ.get("NODE_IP", "")

TOPO = T.load(TOPO_PATH)
HUB = next(h for h, hc in TOPO["hosts"].items() if hc.get("kind") == "hub")
AGENT_PORT = TOPO["agent_port"]
ZONE_ORDER = list(TOPO["zones"])

app = FastAPI(title="Klinikum NetOps-Portal", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(HERE / "templates")), autoescape=True)

STATE: dict = {"matrix": {"ts": None, "running": False, "results": [], "mismatches": 0, "checks": 0, "duration_s": 0}}
WEBHOOK_ALERTS: list[dict] = []
STATE_LOCK = threading.Lock()


# --------------------------------------------------------------------------
# Hilfsfunktionen
# --------------------------------------------------------------------------
def render(name: str, request: Request, **ctx) -> HTMLResponse:
    tpl = env.get_template(name)
    return HTMLResponse(tpl.render(request=request, page=name.split(".")[0], title=TOPO["name"],
                                   grafana=GRAFANA_URL, prometheus=PROM_URL, **ctx))


def local_probe(host: str, port: int, timeout: float = 0.8) -> dict:
    import socket
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            ok, err = True, None
    except OSError as exc:
        ok, err = False, type(exc).__name__
    return {"host": host, "port": port, "ok": ok, "ms": round((time.perf_counter() - t0) * 1000, 1), "error": err}


def node_status(host: str) -> dict:
    hc = TOPO["hosts"][host]
    if hc.get("kind") == "hub":
        return {"host": host, "up": True, "uptime_s": None}
    try:
        r = requests.get(f"http://{hc['ip']}:{AGENT_PORT}/health", timeout=1.5)
        r.raise_for_status()
        return {"host": host, "up": True, "uptime_s": r.json().get("uptime_s")}
    except requests.RequestException:
        return {"host": host, "up": False, "uptime_s": None}


def all_status() -> dict[str, dict]:
    with ThreadPoolExecutor(max_workers=20) as pool:
        return {s["host"]: s for s in pool.map(node_status, TOPO["hosts"])}


def fw_get(path: str) -> dict | None:
    try:
        r = requests.get(f"{FW_URL}{path}", timeout=2)
        r.raise_for_status()
        return r.json()
    except requests.RequestException:
        return None


# --------------------------------------------------------------------------
# Erreichbarkeitsmatrix (Soll gegen Ist)
# --------------------------------------------------------------------------
def run_matrix() -> dict:
    with STATE_LOCK:
        if STATE["matrix"]["running"]:
            return STATE["matrix"]
        STATE["matrix"]["running"] = True
    t0 = time.time()
    expected = T.expected_matrix(TOPO)
    by_src: dict[str, list[dict]] = {}
    for e in expected:
        by_src.setdefault(e["src"], []).append(e)

    def work(src: str):
        items = by_src[src]
        targets = [{"host": TOPO["hosts"][e["dst"]]["ip"], "port": e["port"]} for e in items]
        try:
            if src == HUB:
                with ThreadPoolExecutor(max_workers=24) as pool:
                    res = list(pool.map(lambda t: local_probe(t["host"], t["port"]), targets))
            else:
                r = requests.post(f"http://{TOPO['hosts'][src]['ip']}:{AGENT_PORT}/probe-batch", json={"targets": targets}, timeout=30)
                r.raise_for_status()
                res = r.json()
        except requests.RequestException:
            res = [{"ok": None, "error": "Messpunkt nicht erreichbar", "ms": None} for _ in targets]
        out = []
        for e, r in zip(items, res):
            actual = None if r["ok"] is None else ("allow" if r["ok"] else "deny")
            out.append({**e, "actual": actual, "error": r.get("error"), "ms": r.get("ms"),
                        "match": actual == e["expected"]})
        return out

    with ThreadPoolExecutor(max_workers=20) as pool:
        results = [row for rows in pool.map(work, by_src) for row in rows]
    mismatches = sum(1 for r in results if not r["match"])
    with STATE_LOCK:
        STATE["matrix"] = {"ts": time.time(), "running": False, "results": results, "mismatches": mismatches,
                           "checks": len(results), "duration_s": round(time.time() - t0, 1)}
    return STATE["matrix"]


def background_loop() -> None:
    time.sleep(25)
    while True:
        try:
            run_matrix()
        except Exception as exc:  # Hintergrundjob darf nie sterben
            print("Matrix-Lauf fehlgeschlagen:", exc, flush=True)
            with STATE_LOCK:
                STATE["matrix"]["running"] = False
        time.sleep(MATRIX_INTERVAL)


@app.on_event("startup")
def _startup() -> None:
    if BACKGROUND:
        threading.Thread(target=background_loop, daemon=True).start()


# --------------------------------------------------------------------------
# Topologie-Grafik (SVG, serverseitig)
# --------------------------------------------------------------------------
def topology_svg(status: dict[str, dict], zones_state: dict[str, bool]) -> str:
    top = [z for z in ("internet", "dmz", "mgmt", "gast") if z in TOPO["zones"]]
    bottom = [z for z in ZONE_ORDER if z not in top]
    W, boxw, boxh, gap = 1000, 176, 190, 12
    fw_y, fw_h = 258, 44
    parts = [f'<svg viewBox="0 0 {W} 560" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Netzwerktopologie">']
    parts.append(f'<rect class="fw" x="40" y="{fw_y}" width="{W-80}" height="{fw_h}" rx="8"/>')
    parts.append(f'<text class="fwt" x="{W/2}" y="{fw_y+27}" text-anchor="middle">Firewall (nftables): Standard ist alles verboten</text>')

    def row(zs, y, to_y):
        total = len(zs) * boxw + (len(zs) - 1) * gap
        x0 = (W - total) / 2
        for i, z in enumerate(zs):
            x = x0 + i * (boxw + gap)
            iso = zones_state.get(z, False)
            parts.append(f'<line class="link{" iso" if iso else ""}" x1="{x+boxw/2}" y1="{to_y}" x2="{x+boxw/2}" y2="{fw_y if y < fw_y else fw_y+fw_h}"/>')
            parts.append(f'<rect class="zone{" iso" if iso else ""}" x="{x}" y="{y}" width="{boxw}" height="{boxh}" rx="10"/>')
            zc = TOPO["zones"][z]
            parts.append(f'<text class="zt" x="{x+10}" y="{y+22}">{html.escape(str(z))} · VLAN {zc["vlan"]}</text>')
            parts.append(f'<text class="zc" x="{x+10}" y="{y+38}">{zc["cidr"]}{" · ISOLIERT" if iso else ""}</text>')
            hosts = [h for h, hc in TOPO["hosts"].items() if hc["zone"] == z]
            for j, h in enumerate(hosts[:6]):
                up = status.get(h, {}).get("up", False)
                cy = y + 62 + j * 20
                parts.append(f'<circle class="dot {"up" if up else "down"}" cx="{x+16}" cy="{cy-4}" r="5"/>')
                parts.append(f'<text class="hn" x="{x+28}" y="{cy}">{html.escape(str(h))}</text>')

    row(top, 24, 24 + boxh)
    row(bottom, 340, 340)
    parts.append("</svg>")
    return "".join(parts)


# --------------------------------------------------------------------------
# Seiten
# --------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    status = all_status()
    zones = fw_get("/zones")
    zstate = {z: v["isolated"] for z, v in zones["zones"].items()} if zones else {}
    m = STATE["matrix"]
    return render("index.html", request, svg=topology_svg(status, zstate), status=status, zones=TOPO["zones"], hosts=TOPO["hosts"],
                  fw_ok=zones is not None, isolated=[z for z, v in zstate.items() if v], matrix=m,
                  up=sum(1 for s in status.values() if s["up"]), total=len(status))


@app.get("/matrix", response_class=HTMLResponse)
def matrix_page(request: Request):
    return render("matrix.html", request, zones=TOPO["zones"], hosts=TOPO["hosts"], interval=MATRIX_INTERVAL)


@app.get("/firewall", response_class=HTMLResponse)
def firewall_page(request: Request):
    return render("firewall.html", request, zones=TOPO["zones"], policy=TOPO["policy"], hub=HUB)


@app.get("/services", response_class=HTMLResponse)
def services_page(request: Request):
    rules = T.expand_rules(TOPO)
    rows = []
    for d, dh in TOPO["hosts"].items():
        for svc in dh["services"]:
            proto = "udp" if svc["kind"] == "udp" else "tcp"
            via_vpn, plain = [], []
            for s, sh in TOPO["hosts"].items():
                if sh["zone"] == dh["zone"]:
                    continue
                ok, pid = T.is_allowed(TOPO, s, d, proto, svc["port"], rules)
                if ok:
                    (via_vpn if T.source_ip(TOPO, s, d) != sh["ip"] else plain).append((s, sh["zone"]))
            reach = []
            for z in ZONE_ORDER:
                zh = [h for h, hc in TOPO["hosts"].items() if hc["zone"] == z]
                got = [s for s, sz in plain if sz == z]
                if got and len(got) == len(zh):
                    reach.append(f"Zone {z}")
                else:
                    reach += got
            reach += [f"{s} (per VPN)" for s, _ in via_vpn]
            rows.append({"host": d, "zone": dh["zone"], "title": svc["title"], "name": svc["name"], "port": svc["port"],
                         "proto": proto, "desc": dh["description"], "reach": reach})
    return render("services.html", request, rows=rows)


@app.get("/vpn", response_class=HTMLResponse)
def vpn_page(request: Request):
    gw = TOPO["hosts"][TOPO["vpn"]["gateway"]]
    return render("vpn.html", request, vpn=TOPO["vpn"], gw=gw, zones=TOPO["zones"], hosts=TOPO["hosts"],
                  presets=vpnlive.PRESETS, active_seconds=vpnlive.ACTIVE_SECONDS)


@app.get("/api/vpn")
def api_vpn():
    return vpnlive.fetch(TOPO, AGENT_PORT)


@app.post("/api/vpn/simulate")
async def api_vpn_simulate(request: Request):
    body = await request.json()
    try:
        res = vpnlive.simulate(body.get("peer", ""), body.get("preset"), TOPO)
    except KeyError as exc:
        raise HTTPException(404, "unbekannter Peer") from exc
    except ValueError as exc:
        raise HTTPException(400, "unbekannte Reise") from exc
    return {**res, "state": vpnlive.fetch(TOPO, AGENT_PORT, ttl=0)}


@app.get("/alerts", response_class=HTMLResponse)
def alerts_page(request: Request):
    return render("alerts.html", request)


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------
@app.get("/api/status")
def api_status():
    return all_status()


@app.get("/api/matrix")
def api_matrix():
    return STATE["matrix"]


@app.post("/api/matrix/run")
def api_matrix_run():
    return run_matrix()


@app.get("/api/firewall")
def api_firewall():
    rules, zones = fw_get("/rules"), fw_get("/zones")
    if rules is None or zones is None:
        raise HTTPException(503, "Firewall-Agent nicht erreichbar")
    return {"rules": rules["rules"], "zones": zones["zones"], "events": zones["events"]}


def _fw_post(action: str, zone: str):
    try:
        r = requests.post(f"{FW_URL}/{action}/{zone}", headers={"X-Lab-Token": LAB_TOKEN}, timeout=3)
    except requests.RequestException as exc:
        raise HTTPException(503, "Firewall-Agent nicht erreichbar") from exc
    if r.status_code != 200:
        raise HTTPException(r.status_code, r.json().get("detail", "Fehler"))
    return r.json()


@app.post("/api/isolate/{zone}")
def api_isolate(zone: str):
    return _fw_post("isolate", zone)


@app.post("/api/release/{zone}")
def api_release(zone: str):
    return _fw_post("release", zone)


@app.get("/api/alerts")
def api_alerts():
    try:
        r = requests.get(f"{AM_URL}/api/v2/alerts", timeout=2)
        r.raise_for_status()
        alerts = [{"name": a["labels"].get("alertname"), "severity": a["labels"].get("severity"),
                   "summary": a["annotations"].get("summary", ""), "since": a["startsAt"], "state": a["status"]["state"]}
                  for a in r.json()]
    except requests.RequestException:
        alerts = None
    return {"alerts": alerts, "webhook": WEBHOOK_ALERTS[-20:]}


@app.post("/api/alert-webhook")
async def alert_webhook(request: Request):
    body = await request.json()
    for a in body.get("alerts", []):
        WEBHOOK_ALERTS.append({"t": time.strftime("%H:%M:%S"), "status": a.get("status"), "name": a["labels"].get("alertname"),
                               "summary": a.get("annotations", {}).get("summary", "")})
    del WEBHOOK_ALERTS[:-100]
    return JSONResponse({"ok": True})


# --------------------------------------------------------------------------
# Anwendungen ausprobieren: Browser-Ersatz aus Sicht verschiedener Hosts
# --------------------------------------------------------------------------
def _find_host(kind: str) -> str:
    return next(h for h, hc in TOPO["hosts"].items() if any(sv.get("data") == kind for sv in hc["services"]))


KIS_HOST = _find_host("kis")
PP_HOST = _find_host("patientportal")
KIS_AGENT = f"http://{TOPO['hosts'][KIS_HOST]['ip']}:{AGENT_PORT}"


def _http_port(host: str) -> int:
    return next(sv["port"] for sv in TOPO["hosts"][host]["services"] if sv["kind"] == "http")


APPS = [
    {"title": "Patient im Gäste-WLAN öffnet das Patientenportal", "src": "gast-client", "dst": PP_HOST, "path": "",
     "who": "Patient (P-1001 / PIN 1234)", "lern": "Der Patient sieht nur seine eigenen Daten. Das Portal fragt das KIS (Regel P10), nie die Datenbank."},
    {"title": "Ärztin auf der Station öffnet das KIS", "src": "ws-arzt", "dst": KIS_HOST, "path": "staff",
     "who": "dr.beispiel / arzt-lab", "lern": "Akte mit Befunden, nur Patienten mit Behandlungsbezug. Notfallzugriff mit Begründung."},
    {"title": "Pflege auf der Station öffnet das KIS", "src": "ws-pflege", "dst": KIS_HOST, "path": "staff",
     "who": "schwester.test / pflege-lab", "lern": "Medikation ja, Befunde nein, kein Notfallzugriff."},
    {"title": "Empfang (Verwaltung) öffnet das KIS", "src": "ws-verwaltung", "dst": KIS_HOST, "path": "staff",
     "who": "empfang.lab / empfang-lab", "lern": "Termine vergeben, aber keine Akte und keine Abrechnung."},
    {"title": "Abrechnung (Verwaltung) öffnet das KIS", "src": "ws-verwaltung", "dst": KIS_HOST, "path": "staff",
     "who": "abrechnung.lab / abrechnung-lab", "lern": "Rechnungen und Beträge, keine Diagnosen, keine Termine."},
    {"title": "IT-Administration aus der Management-Zone", "src": HUB, "dst": KIS_HOST, "path": "staff",
     "who": "admin.lab / admin-lab", "lern": "Sieht das Protokoll, aber keine Patientendaten (Datenschutz)."},
    {"title": "Dienst-Handy der Ärztin per VPN", "src": "aerztin-handy", "dst": KIS_HOST, "path": "staff",
     "who": "dr.beispiel / arzt-lab", "lern": "Der Zugriff läuft durch den Tunnel. Die Firewall erlaubt nur das KIS (Regel P15)."},
    {"title": "Gast versucht, das KIS direkt zu öffnen", "src": "gast-client", "dst": KIS_HOST, "path": "staff",
     "who": "kein Zugang", "lern": "Die Firewall verwirft die Verbindung. Auf Netzebene scheitert es, bevor eine Anmeldung möglich ist."},
    {"title": "MRT versucht, das KIS zu öffnen", "src": "mrt", "dst": KIS_HOST, "path": "staff",
     "who": "kein Zugang", "lern": "Medizingeräte dürfen nur zum PACS. Alles andere ist verboten."},
]


@app.get("/apps", response_class=HTMLResponse)
def apps_page(request: Request):
    rows = []
    for a in APPS:
        ok, rule = T.is_allowed(TOPO, a["src"], a["dst"], "tcp", _http_port(a["dst"]))
        rows.append({**a, "zone": TOPO["hosts"][a["src"]]["zone"], "allowed": ok, "rule": rule,
                     "url": f"/via/{a['src']}/{a['dst']}/{a['path']}", "port": _http_port(a["dst"])})
    return render("apps.html", request, rows=rows)


@app.api_route("/via/{src}/{dst}/{path:path}", methods=["GET", "POST"])
async def via(src: str, dst: str, path: str, request: Request):
    """Öffnet eine Seite so, als säße der Browser auf dem Host src. Die Anfrage läuft über dessen Messpunkt
    und durch die echte Firewall. Cookies und Formulare werden durchgereicht."""
    if src not in TOPO["hosts"] or dst not in TOPO["hosts"] or src == dst:
        raise HTTPException(404, "unbekannter Host")
    if not any(sv["kind"] == "http" for sv in TOPO["hosts"][dst]["services"]):
        raise HTTPException(404, "Ziel hat keinen Web-Dienst")
    port = _http_port(dst)
    url = f"http://{TOPO['hosts'][dst]['ip']}:{port}/{path}" + (f"?{request.url.query}" if request.url.query else "")
    body = await request.body()
    hdr = {"X-Prefix": f"/via/{src}/{dst}"}
    for k in ("cookie", "content-type"):
        if request.headers.get(k):
            hdr[k.title() if k == "cookie" else "Content-Type"] = request.headers[k]

    def go() -> dict:
        if src == HUB:
            try:
                r = requests.request(request.method, url, data=body or None, headers=hdr, timeout=5, allow_redirects=False)
            except requests.RequestException as exc:
                return {"ok": False, "from": src, "zone": TOPO["hosts"][src]["zone"], "error": type(exc).__name__, "detail": str(exc)[:120]}
            return {"ok": True, "status": r.status_code, "content_type": r.headers.get("Content-Type", "text/html"),
                    "set_cookie": r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw.headers, "getlist") else ([r.headers["Set-Cookie"]] if "Set-Cookie" in r.headers else []),
                    "location": r.headers.get("Location"), "body_b64": base64.b64encode(r.content).decode(), "from": src}
        try:
            r = requests.post(f"http://{TOPO['hosts'][src]['ip']}:{AGENT_PORT}/fetch", headers={"X-Lab-Token": LAB_TOKEN}, timeout=10,
                              json={"url": url, "method": request.method, "headers": hdr, "body_b64": base64.b64encode(body).decode() if body else ""})
            r.raise_for_status()
            return r.json()
        except requests.RequestException as exc:
            return {"ok": False, "from": src, "zone": TOPO["hosts"][src]["zone"], "error": "Messpunkt nicht erreichbar", "detail": str(exc)[:120]}

    res = await run_in_threadpool(go)
    if not res.get("ok"):
        ok, rule = T.is_allowed(TOPO, src, dst, "tcp", port)
        return render("via_error.html", request, src=src, dst=dst, port=port, zone=TOPO["hosts"][src]["zone"], dzone=TOPO["hosts"][dst]["zone"],
                      res=res, should_allow=ok, rule=rule)
    out = Response(content=base64.b64decode(res["body_b64"]), status_code=res["status"], media_type=None)
    out.headers["Content-Type"] = res.get("content_type") or "text/html"
    if res.get("location"):
        out.headers["Location"] = res["location"]
    for c in res.get("set_cookie") or []:
        out.headers.append("set-cookie", c)
    out.headers["Cache-Control"] = "no-store"
    return out


# --------------------------------------------------------------------------
# Backup und Ransomware-Simulation des KIS
# --------------------------------------------------------------------------
_KIS_CACHE: dict = {"t": 0.0, "data": None}


def kis_status(max_age: float = 2.0) -> dict | None:
    if time.time() - _KIS_CACHE["t"] < max_age:
        return _KIS_CACHE["data"]
    try:
        r = requests.get(f"{KIS_AGENT}/kis/status", timeout=2)
        r.raise_for_status()
        _KIS_CACHE.update(t=time.time(), data=r.json())
    except requests.RequestException:
        _KIS_CACHE.update(t=time.time(), data=None)
    return _KIS_CACHE["data"]


def backup_metrics(st: dict | None) -> list[str]:
    if st is None:
        return ["# TYPE lab_kis_reachable gauge", "lab_kis_reachable 0"]
    bk = st["backups"]
    age = (st["now"] - st["last_backup_ts"]) if st["last_backup_ts"] else 999999
    imm = sum(1 for b in bk if b["immutable"])
    return [
        "# TYPE lab_kis_reachable gauge", "lab_kis_reachable 1",
        "# TYPE lab_kis_locked gauge", f"lab_kis_locked {1 if st['locked'] else 0}",
        "# TYPE lab_backup_age_seconds gauge", f"lab_backup_age_seconds {age:.0f}",
        "# TYPE lab_backup_count gauge", f"lab_backup_count {len(bk)}",
        "# TYPE lab_backup_immutable_count gauge", f"lab_backup_immutable_count {imm}",
        "# TYPE lab_backup_immutable_ratio gauge", f"lab_backup_immutable_ratio {(imm / len(bk)) if bk else 0:.2f}",
        "# TYPE lab_backup_changes_since gauge", f"lab_backup_changes_since {st['changes_seit_backup'] or 0}",
        "# TYPE lab_backup_restore_ms gauge", f"lab_backup_restore_ms {st['restore_ms']:.1f}",
    ]


@app.get("/backup", response_class=HTMLResponse)
def backup_page(request: Request):
    return render("backup.html", request)


@app.get("/api/backup/status")
def api_backup_status():
    st = kis_status(0)
    if st is None:
        raise HTTPException(503, "KIS-Messpunkt nicht erreichbar")
    return st


_BACKUP_ACTIONS = {"run": "backup", "verify": "verify", "ransom": "ransom", "restore": "restore", "worm": "worm", "reset": "reset"}


@app.post("/api/backup/{action}")
async def api_backup_action(action: str, request: Request):
    if action not in _BACKUP_ACTIONS:
        raise HTTPException(404, "unbekannte Aktion")
    try:
        payload = await request.json()
    except ValueError:
        payload = {}
    try:
        r = await run_in_threadpool(lambda: requests.post(f"{KIS_AGENT}/kis/{_BACKUP_ACTIONS[action]}", json=payload,
                                                          headers={"X-Lab-Token": LAB_TOKEN}, timeout=6))
    except requests.RequestException as exc:
        raise HTTPException(503, "KIS-Messpunkt nicht erreichbar") from exc
    _KIS_CACHE["t"] = 0
    if r.status_code != 200:
        raise HTTPException(r.status_code, r.json().get("detail", "Fehler"))
    return r.json()


@app.get("/metrics", response_class=PlainTextResponse)
def metrics():
    m = STATE["matrix"]
    lines = [
        "# TYPE lab_policy_mismatch gauge", f"lab_policy_mismatch {m['mismatches']}",
        "# TYPE lab_matrix_checks gauge", f"lab_matrix_checks {m['checks']}",
        "# TYPE lab_matrix_last_run_timestamp_seconds gauge", f"lab_matrix_last_run_timestamp_seconds {m['ts'] or 0:.0f}",
    ]
    lines += vpnlive.metrics_lines(vpnlive.fetch(TOPO, AGENT_PORT))
    lines += backup_metrics(kis_status())
    return "\n".join(lines) + "\n"


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host=BIND_IP or "0.0.0.0", port=int(os.environ.get("PORT", "8080")), log_level="warning")
