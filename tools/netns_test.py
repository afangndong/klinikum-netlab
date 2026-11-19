#!/usr/bin/env python3
"""Ende-zu-Ende-Test ohne Docker: echte Firewall-Regeln in Linux-Network-Namespaces.

Baut das Lab aus topology/klinikum.yml nach (ein Namespace pro Host, eine Firewall als
Router mit einer Bridge pro Zone), lädt die ECHTE build/fw/nftables.conf mit echtem nft,
startet den echten Knoten-Code (docker/node.py), den echten Firewall-Agent
(docker/fw_agent.py) und das echte Portal (docker/portal/app.py) und prüft:

  1. Erreichbarkeitsmatrix: Ist-Verhalten == Policy (alle TCP-Dienste, alle Quellen)
  2. UDP/51820 (VPN-Port) aus dem Internet zum Gateway erlaubt, sonst nicht
  3. Zählertreffer der Regeln im Agent und im Portal
  4. Drift-Erkennung: eine heimlich ergänzte Regel wird als Abweichung gemeldet
  5. Notfall-Isolation einer Zone per API und Freigabe
  6. Die mgmt-Zone kann nicht isoliert werden, falsches Token wird abgelehnt

Grenze: WireGuard selbst wird hier NICHT getestet (Tunnel werden nachgebildet: Clients
senden mit der Tunnel-Quelladresse). Das echte VPN läuft nur im Docker-Lab.

Aufruf (als root):  sudo python tools/netns_test.py
"""
from __future__ import annotations

import ipaddress
import json
import os
import shlex
import signal
import tempfile
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from netlab import topology as T  # noqa: E402

PFX = "kl-"
FW = PFX + "fw"
TOKEN = "test-token"
procs: list[subprocess.Popen] = []
results: list[tuple[str, bool, str]] = []


def sh(cmd: str, check=True, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True, **kw)


def ns_run(ns: str, cmd: str, **kw):
    return sh(f"ip netns exec {ns} sh -c {shlex.quote(cmd)}", **kw)


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(("  ok   " if ok else "  FAIL ") + name + (f"  [{detail}]" if detail and not ok else ""), flush=True)


def cleanup() -> None:
    for p in procs:
        try:
            p.send_signal(signal.SIGTERM)
        except Exception:
            pass
    for p in procs:
        try:
            p.wait(timeout=3)
        except Exception:
            p.kill()
    out = sh("ip netns list", check=False).stdout
    for line in out.splitlines():
        name = line.split()[0]
        if name.startswith(PFX):
            sh(f"ip netns del {name}", check=False)


def spawn(ns: str, argv: list[str], env: dict) -> subprocess.Popen:
    full = {**os.environ, **env}
    p = subprocess.Popen(["ip", "netns", "exec", ns, *argv], env=full, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    procs.append(p)
    return p


def wait_for(ns: str, ip: str, port: int, tries=60) -> bool:
    code = f"import socket,sys;s=socket.socket();s.settimeout(0.5);s.connect(('{ip}',{port}))"
    for _ in range(tries):
        if ns_run(ns, f"python3 -c \"{code}\"", check=False).returncode == 0:
            return True
        time.sleep(0.25)
    return False


def build(t: dict) -> None:
    sh(f"ip netns add {FW}")
    ns_run(FW, "sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0")
    ns_run(FW, "ip link set lo up")
    for z, zc in t["zones"].items():
        gw = T.zone_gateway(t, z)
        plen = ipaddress.ip_network(zc["cidr"]).prefixlen
        ns_run(FW, f"ip link add br-{z} type bridge && ip addr add {gw}/{plen} dev br-{z} && ip link set br-{z} up")
    pool = t["vpn"]["pool"]
    for i, (h, hc) in enumerate(t["hosts"].items()):
        ns = PFX + h
        z = hc["zone"]
        plen = ipaddress.ip_network(t["zones"][z]["cidr"]).prefixlen
        gw = T.zone_gateway(t, z)
        sh(f"ip netns add {ns}")
        sh(f"ip link add vh{i} type veth peer name vf{i}")
        sh(f"ip link set vh{i} netns {ns} && ip link set vf{i} netns {FW}")
        ns_run(FW, f"ip link set vf{i} master br-{z} && ip link set vf{i} up")
        ns_run(ns, f"ip link set lo up && ip link set vh{i} name eth0 && ip addr add {hc['ip']}/{plen} dev eth0 && ip link set eth0 up")
        ns_run(ns, "sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0")
        ns_run(ns, f"ip route add {t['supernet']} via {gw}")
        peer = hc.get("vpn_peer")
        if peer:
            pc = t["vpn"]["peers"][peer]
            # Tunnel nachbilden: Tunneladresse am Client, Routen in freigegebene Zonen mit dieser Quelladresse.
            ns_run(ns, f"ip addr add {pc['address']}/32 dev eth0")
            for az in pc["allowed_zones"]:
                ns_run(ns, f"ip route replace {t['zones'][az]['cidr']} via {gw} src {pc['address']}")
            ns_run(FW, f"ip route add {pc['address']}/32 dev br-{z} via {hc['ip']}", check=False)
        elif hc.get("role") != "vpn-gateway":
            ns_run(ns, f"ip route add {pool} via {gw}")
    sh(f"ip netns exec {FW} nft -f {ROOT / 'build/fw/nftables.conf'}")


def make_fake_wg(t: dict) -> str:
    """Ersatz für `wg show wg0 dump` (echtes WireGuard läuft hier nicht). Gleiches Ausgabeformat wie das Original."""
    d = tempfile.mkdtemp(prefix="klfake-")
    peers = []
    for i, (name, pc) in enumerate(t["vpn"]["peers"].items()):
        peers.append({"key": f"FAKEKEY{i}=", "ips": pc["address"] + "/32", "age": None if name == "aerztin-handy" else 20 + i * 10,
                      "rx": 1500000 + i, "tx": 400000 + i})
    script = f"""#!/usr/bin/env python3
import sys,time
if sys.argv[1:] != ["show","wg0","dump"]:
    sys.exit(1)
print("PRIVATEKEY-GEHEIM\\tGWPUB=\\t{t['vpn']['listen_port']}\\toff")
for p in {peers!r}:
    hs = 0 if p["age"] is None else int(time.time()) - p["age"]
    ep = "(none)" if p["age"] is None else "203.0.113.7:51000"
    print("\\t".join([p["key"], "(none)", ep, p["ips"], str(hs), str(p["rx"]), str(p["tx"]), "15"]))
"""
    path = os.path.join(d, "wg")
    Path(path).write_text(script)
    os.chmod(path, 0o755)
    return path


def start_nodes(t: dict) -> None:
    fake = make_fake_wg(t)
    for h, hc in t["hosts"].items():
        if hc.get("kind") == "hub":
            continue
        env = {"NODE_NAME": h, "NODE_ZONE": hc["zone"], "NODE_IP": hc["ip"], "NODE_TITLE": hc["title"],
               "NODE_DESCRIPTION": hc["description"], "NODE_SERVICES": json.dumps(hc["services"]),
               "AGENT_PORT": str(t["agent_port"]), "ROLE": hc.get("role", "node"), "WG_BIN": fake, "LAB_TOKEN": TOKEN}
        if any(sv.get("data") == "patientportal" for sv in hc["services"]):
            kh = next(x for x in t["hosts"].values() if any(sv.get("data") == "kis" for sv in x["services"]))
            env["KIS_URL"] = f"http://{kh['ip']}:8080"
        spawn(PFX + h, [sys.executable, str(ROOT / "docker/node.py")], env)


def hub_py(code: str, timeout=120) -> subprocess.CompletedProcess:
    return subprocess.run(["ip", "netns", "exec", PFX + HUB, sys.executable, "-c", code],
                          capture_output=True, text=True, timeout=timeout)


def hub_json(method: str, path: str, headers: dict | None = None, port=8080, host="127.0.0.1"):
    code = (f"import requests,json;r=requests.request('{method}','http://{host}:{port}{path}',headers={headers or {}!r},timeout=100);"
            "print(json.dumps({'status':r.status_code,'body':r.json()}))")
    cp = hub_py(code)
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr[-400:])
    return json.loads(cp.stdout)


def main() -> int:
    global HUB
    if os.geteuid() != 0:
        print("Bitte als root ausführen (Namespaces und nftables brauchen das).", file=sys.stderr)
        return 2
    subprocess.run([sys.executable, str(ROOT / "tools/render.py")], check=True, capture_output=True)
    t = T.load(ROOT / "topology/klinikum.yml")
    HUB = next(h for h, hc in t["hosts"].items() if hc.get("kind") == "hub")
    hub_cfg = t["hosts"][HUB]
    fw_mgmt = T.zone_gateway(t, hub_cfg["zone"])
    api = t["firewall"]["api_port"]
    expected = T.expected_matrix(t)
    n_allow = sum(1 for e in expected if e["expected"] == "allow")
    cleanup()
    try:
        print("Baue Netz auf …")
        build(t)
        check("nftables geladen (echte Regeldatei)", ns_run(FW, "nft list chain ip klinikum forward", check=False).returncode == 0)
        start_nodes(t)
        # Firewall-Agent in der Firewall-Namespace
        spawn(FW, [sys.executable, str(ROOT / "docker/fw_agent.py")],
              {"POLICY_FILE": str(ROOT / "build/policy.json"), "LAB_TOKEN": TOKEN, "FW_BIND": fw_mgmt, "FW_PORT": str(api)})
        # Portal im Hub
        spawn(PFX + HUB, [sys.executable, "-m", "uvicorn", "portal.app:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "warning"],
              {"PYTHONPATH": f"{ROOT}:{ROOT / 'docker'}", "TOPOLOGY": str(ROOT / "topology/klinikum.yml"),
               "FW_URL": f"http://{fw_mgmt}:{api}", "LAB_TOKEN": TOKEN, "MATRIX_BACKGROUND": "0"})
        for svc in hub_cfg["services"]:
            if svc["port"] != 8080 and svc["kind"] in ("http", "tcp"):
                spawn(PFX + HUB, [sys.executable, "-c",
                      f"import socket,time;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',{svc['port']}));s.listen(16)\n"
                      "while True:\n c,_=s.accept();c.close()"], {})
        ready = wait_for(PFX + HUB, "127.0.0.1", 8080) and wait_for(PFX + HUB, fw_mgmt, api)
        check("Portal und Firewall-Agent gestartet", ready)
        if not ready:
            for p in procs:
                if p.poll() is not None:
                    print((p.stderr.read() or b"")[-800:].decode(errors="replace"))
            return 1
        time.sleep(1.5)

        st = hub_json("GET", "/api/status")["body"]
        down = [h for h, s in st.items() if not s["up"]]
        check(f"alle {len(st)} Knoten melden sich beim Portal", not down, f"down: {down}")

        print("Erreichbarkeitsmatrix (Soll gegen Ist) …")
        t0 = time.time()
        m = hub_json("POST", "/api/matrix/run")["body"]
        check(f"Matrix komplett: {m['checks']} Prüfungen", m["checks"] == len(expected), f"{m['checks']} != {len(expected)}")
        bad = [r for r in m["results"] if not r["match"]]
        check(f"Ist == Soll bei allen {m['checks']} Prüfungen ({n_allow} erlaubt, {m['checks']-n_allow} verboten)", not bad,
              "; ".join(f"{r['src']}->{r['dst']}:{r['port']} soll {r['expected']} ist {r['actual']}" for r in bad[:6]))
        got_allow = sum(1 for r in m["results"] if r["actual"] == "allow")
        check("Anzahl erlaubter Verbindungen stimmt", got_allow == n_allow, f"{got_allow} != {n_allow}")
        print(f"      (Dauer {time.time()-t0:.0f}s)")

        # gezielte Beispiele aus dem Pflichtenheft des Klinikums
        by = {(r["src"], r["dst"], r["port"]): r["actual"] for r in m["results"]}
        for (s, d, p), want in [(("mrt", "pacs", 4242), "allow"), (("mrt", "kis", 8080), "deny"),
                                (("mrt", "db", 5432), "deny"), (("gast-client", "kis", 8080), "deny"),
                                (("gast-client", "patientenportal", 8080), "allow"), (("kis", "db", 5432), "allow"),
                                (("ws-arzt", "db", 5432), "deny"), (("admin-laptop", "mgmt-hub", 8080), "allow"),
                                (("admin-laptop", "kis", 8080), "deny"), (("mvz-aussenstelle", "kis", 8080), "allow"),
                                (("mvz-aussenstelle", "mgmt-hub", 8080), "deny")]:
            check(f"{s} -> {d}:{p} = {want}", by.get((s, d, p)) == want, str(by.get((s, d, p))))

        # UDP/51820: Internet -> VPN-Gateway
        gw = t["hosts"][t["vpn"]["gateway"]]["ip"]
        port = t["vpn"]["listen_port"]
        spawn(PFX + t["vpn"]["gateway"], [sys.executable, "-c",
              f"import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',{port}))\n"
              "while True:\n d,a=s.recvfrom(100);s.sendto(b'pong',a)"], {})
        time.sleep(0.5)
        udp = ("import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(1);s.sendto(b'x',('%s',%d))\n"
               "try:\n s.recvfrom(10);print('ok')\nexcept Exception:\n print('timeout')")
        r1 = ns_run(PFX + "mvz-aussenstelle", f"python3 -c \"{udp % (gw, port)}\"", check=False).stdout.strip()
        r2 = ns_run(PFX + "mvz-aussenstelle", f"python3 -c \"{udp % (gw, 51821)}\"", check=False).stdout.strip()
        r3 = ns_run(PFX + "gast-client", f"python3 -c \"{udp % (gw, port)}\"", check=False).stdout.strip()
        check("UDP/51820 Internet -> VPN-Gateway erlaubt", r1 == "ok", r1)
        check("anderer UDP-Port zum Gateway verworfen", r2 == "timeout", r2)
        check("Gast-WLAN erreicht den VPN-Port nicht", r3 == "timeout", r3)

        # VPN-Live (mit Ersatz für `wg`)
        print("VPN-Live …")
        raw = hub_py(f"import requests;print(requests.get('http://{gw}:{t['agent_port']}/wg').text)").stdout
        check("Agent /wg liefert Peers und gibt keinen privaten Schlüssel aus", raw.count("public_key") >= 4 and "GEHEIM" not in raw, raw[:120])
        v = hub_json("GET", "/api/vpn")["body"]
        names = {p["peer"]: p for p in v["peers"]}
        check("VPN-Live: Gateway erreichbar, 2 von 3 Peers aktiv", v["gateway"]["reachable"] and v["active"] == 2, str(v["active"]))
        check("VPN-Live: Peer ohne Handshake ist getrennt", names["aerztin-handy"]["up"] is False and names["aerztin-handy"]["handshake_age_s"] is None)
        check("VPN-Live: Zuordnung Tunnel-IP -> Peername und Traffic", names["admin-laptop"]["up"] and names["admin-laptop"]["rx_bytes"] == 1500000)
        check("VPN-Live: Standort aus Topologie, kein Alarm", v["unexpected"] == 0 and names["mvz-aussenstelle"]["location"]["city"] == "Kehl")
        sim = hub_py("import requests,json;r=requests.post('http://127.0.0.1:8080/api/vpn/simulate',json={'peer':'admin-laptop','preset':'sao-paulo'});print(json.dumps(r.json()))").stdout
        sj = json.loads(sim)
        check("Reise nach São Paulo: Standort BR, unerwartetes Land", sj["state"]["unexpected"] == 1 and
              next(p for p in sj["state"]["peers"] if p["peer"] == "admin-laptop")["location"]["country"] == "BR")
        pm = hub_py("import requests;print(requests.get('http://127.0.0.1:8080/metrics').text)").stdout
        check("Metrik lab_vpn_peer_geo_unexpected = 1 für admin-laptop", 'lab_vpn_peer_geo_unexpected{peer="admin-laptop",device="laptop",country="BR"} 1' in pm)
        check("Metriken lab_vpn_peers_active und lab_vpn_peer_location vorhanden", "lab_vpn_peers_active 2" in pm and "lab_vpn_peer_location{" in pm)
        sim = hub_py("import requests,json;r=requests.post('http://127.0.0.1:8080/api/vpn/simulate',json={'peer':'admin-laptop','preset':'reset'});print(json.dumps(r.json()))").stdout
        check("Zurücksetzen: wieder kein Alarm", json.loads(sim)["state"]["unexpected"] == 0)
        bad = hub_py("import requests;print(requests.post('http://127.0.0.1:8080/api/vpn/simulate',json={'peer':'nope','preset':'berlin'}).status_code)").stdout.strip()
        check("unbekannter Peer wird abgelehnt (404)", bad == "404", bad)
        page = hub_py("import requests;r=requests.get('http://127.0.0.1:8080/vpn');print(r.status_code, 'Wer ist wo' in r.text)").stdout.strip()
        check("Seite /vpn rendert", page == "200 True", page)

        # Zähler
        fwd = hub_json("GET", "/api/firewall")["body"]
        cnt = {r["id"]: r["packets"] for r in fwd["rules"]}
        check("Trefferzähler: erlaubte Regeln P05 und P08 haben Pakete", cnt.get("P05", 0) > 0 and cnt.get("P08", 0) > 0, str({k: cnt.get(k) for k in ("P05", "P08")}))
        check("Trefferzähler: default-deny hat Pakete", cnt.get("default-deny", 0) > 0)
        fm = hub_py(f"import requests;print(requests.get('http://{fw_mgmt}:{api}/metrics').text)").stdout
        check("fw-Metriken im Prometheus-Format", 'lab_fw_rule_packets_total{rule="default-deny"}' in fm and 'lab_fw_zone_isolated{zone="klinik"} 0' in fm)

        # Drift: heimlich ergänzte Regel
        print("Drift-Erkennung …")
        ns_run(FW, "nft insert rule ip klinikum forward position 0 ip saddr 10.10.50.0/24 ip daddr 10.10.20.10 tcp dport 8080 accept")
        m2 = hub_json("POST", "/api/matrix/run")["body"]
        drift = [r for r in m2["results"] if not r["match"]]
        check("heimlich geöffnete Regel (mrt -> kis) wird als Abweichung gemeldet",
              any(r["src"] == "mrt" and r["dst"] == "kis" and r["port"] == 8080 for r in drift), f"{len(drift)} Abweichungen")
        check("Portal-Metrik lab_policy_mismatch > 0", "lab_policy_mismatch 0" not in hub_py("import requests;print(requests.get('http://127.0.0.1:8080/metrics').text)").stdout)
        listing = ns_run(FW, "nft -a list chain ip klinikum forward").stdout
        handle = next((ln.rsplit("# handle ", 1)[1].strip() for ln in listing.splitlines()
                       if "ip saddr 10.10.50.0/24" in ln and "10.10.20.10" in ln and "counter" not in ln and "# handle" in ln), None)
        check("heimlich eingefügte Regel gefunden", handle is not None)
        if handle:
            ns_run(FW, f"nft delete rule ip klinikum forward handle {handle}")
        m3 = hub_json("POST", "/api/matrix/run")["body"]
        check("nach Entfernen der Regel wieder 0 Abweichungen", m3["mismatches"] == 0, f"{m3['mismatches']}")

        # Notfall-Isolation
        print("Notfall-Isolation …")
        r = hub_json("POST", "/api/isolate/klinik")
        check("Zone klinik isolieren (API)", r["status"] == 200 and r["body"]["isolated"] is True, str(r))
        kis = t["hosts"]["kis"]["ip"]

        def can_connect(src: str, dst_ip: str, port: int = 8080) -> bool:
            code = f"import socket;s=socket.socket();s.settimeout(1);s.connect(('{dst_ip}',{port}))"
            return ns_run(PFX + src, f"python3 -c \"{code}\"", check=False).returncode == 0

        check("isoliert: ws-arzt erreicht kis nicht mehr", not can_connect("ws-arzt", kis))
        check("isoliert: auch der Messpunkt der Zone ist vom Hub aus abgeschnitten",
              not can_connect(HUB, t["hosts"]["ws-arzt"]["ip"], t["agent_port"]))
        zs = hub_json("GET", "/api/firewall")["body"]["zones"]
        check("Portal zeigt klinik als isoliert", zs["klinik"]["isolated"] is True)
        check("andere Zone (verwaltung) bleibt arbeitsfähig", can_connect("ws-verwaltung", kis))
        r = hub_json("POST", "/api/release/klinik")
        check("Freigabe: ws-arzt erreicht kis wieder", r["status"] == 200 and can_connect("ws-arzt", kis))
        r = hub_json("POST", "/api/isolate/mgmt")
        check("mgmt-Zone lässt sich nicht isolieren", r["status"] == 409, str(r["status"]))
        r = hub_py(f"import requests;print(requests.post('http://{fw_mgmt}:{api}/isolate/klinik',headers={{'X-Lab-Token':'falsch'}}).status_code)").stdout.strip()
        check("falsches Token wird abgelehnt (401)", r == "401", r)
        # Agent nur aus mgmt erreichbar
        r = ns_run(PFX + "ws-arzt", f"python3 -c \"import socket;s=socket.socket();s.settimeout(1);s.connect(('{T.zone_gateway(t, 'klinik')}',{api}))\"", check=False)
        check("Firewall-Agent ist aus der Klinik-Zone nicht erreichbar", r.returncode != 0)

        # Anwendungen: Patientenportal, KIS mit Rollen, Backup (durch die echte Firewall)
        print("Anwendungen (Patientenportal, KIS-Rollen, Backup) …")
        prog = """
import requests, json, re
B = 'http://127.0.0.1:8080/via/'
out = {}
s = requests.Session()
P = B + 'gast-client/patientenportal'
r = s.get(P + '/'); out['p_form'] = r.status_code == 200 and 'Anmelden' in r.text and 'action="/via/gast-client/patientenportal/login"' in r.text
r = s.post(P + '/login', data={'pid': 'P-1001', 'pin': '1234'}, allow_redirects=False)
out['p_login'] = r.status_code == 303 and 'Path=/via/gast-client/patientenportal' in r.headers.get('set-cookie', '')
r = s.get(P + '/akte'); out['p_akte'] = r.status_code == 200 and 'Bluthochdruck' in r.text and 'Knöchelfraktur' not in r.text
r = s.get(P + '/rechnungen'); out['p_rechnung'] = 'R-2026-0001' in r.text and 'R-2026-0003' not in r.text
r = s.get(P + '/archiv/dok?id=A-2018-0102'); out['p_fremd'] = r.status_code == 403
r = s.get(P + '/termine'); csrf = re.search(r'name=csrf value="([^"]+)"', r.text).group(1)
import datetime as dt
d = dt.date.today() + dt.timedelta(days=2)
while d.weekday() >= 5: d += dt.timedelta(days=1)
r = s.post(P + '/termine/neu', data={'csrf': csrf, 'abteilung': 'Orthopädie', 'datum': d.isoformat(), 'zeit': '08:30'}, allow_redirects=False)
out['p_termin'] = r.status_code == 303 and 'msg=' in r.headers.get('location', '')
def staff(src, user, pw):
    ss = requests.Session(); K = B + src + '/kis/staff'
    ss.post(K + '/login', data={'user': user, 'pw': pw}, allow_redirects=False)
    return ss, K
a, K = staff('ws-arzt', 'dr.beispiel', 'arzt-lab')
out['k_arzt'] = 'Erika Beispiel' in a.get(K + '/patienten').text and 'Max Mustermann' not in a.get(K + '/patienten').text
out['k_arzt_abr'] = a.get(K + '/abrechnung').status_code == 403
e, K = staff('ws-verwaltung', 'empfang.lab', 'empfang-lab')
out['k_empfang_akte'] = e.get(K + '/patient?id=P-1001').status_code == 403
out['k_empfang_termine'] = e.get(K + '/termine').status_code == 200
b, K = staff('ws-verwaltung', 'abrechnung.lab', 'abrechnung-lab')
t = b.get(K + '/abrechnung'); out['k_abr'] = t.status_code == 200 and 'Bluthochdruck' not in t.text
i, K = staff('mgmt-hub', 'admin.lab', 'admin-lab')
out['k_it'] = i.get(K + '/protokoll').status_code == 200 and i.get(K + '/patienten').status_code == 403
h, K = staff('aerztin-handy', 'dr.beispiel', 'arzt-lab')
out['k_vpn'] = h.get(K + '/patienten').status_code == 200
g = requests.get(B + 'gast-client/kis/staff'); out['k_gast_blockiert'] = 'Verbindung nicht möglich' in g.text and 'Das ist erwartet' in g.text
m = requests.get(B + 'mrt/kis/staff'); out['k_mrt_blockiert'] = 'Verbindung nicht möglich' in m.text and 'Das ist erwartet' in m.text
print(json.dumps(out))
"""
        cp = hub_py(prog)
        try:
            o = json.loads(cp.stdout)
        except ValueError:
            o = {}
            print(cp.stderr[-600:])
        labels = {"p_form": "Patientenportal aus dem Gäste-WLAN erreichbar (Präfix, Links)", "p_login": "Patient meldet sich an (Cookie nur für den Präfix-Pfad)",
                  "p_akte": "Patient sieht nur die eigene Akte", "p_rechnung": "Patient sieht nur eigene Rechnungen", "p_fremd": "Fremdes Archivdokument wird verweigert",
                  "p_termin": "Patient bucht einen Termin (Portal → KIS durch die Firewall)",
                  "k_arzt": "KIS: Ärztin sieht nur ihre Patienten (von der Station)", "k_arzt_abr": "KIS: Ärztin hat keinen Zugriff auf die Abrechnung",
                  "k_empfang_akte": "KIS: Empfang darf keine Akte öffnen", "k_empfang_termine": "KIS: Empfang sieht Termine", "k_abr": "KIS: Abrechnung sieht keine Diagnosen",
                  "k_it": "KIS: IT-Admin (Management-Zone) sieht Protokoll, aber keine Patienten", "k_vpn": "KIS: Ärztin per VPN-Handy erreicht das KIS",
                  "k_gast_blockiert": "Gast → KIS wird von der Firewall verworfen (erwartet)", "k_mrt_blockiert": "MRT → KIS wird von der Firewall verworfen (erwartet)"}
        for k, lab in labels.items():
            check(lab, o.get(k) is True)
        fw = hub_json("GET", "/api/firewall")["body"]["rules"]
        hits = {r["id"]: r["packets"] for r in fw}
        check("Firewall-Zähler P09 (Gast → Portal) und P10 (Portal → KIS) zählen", hits.get("P09", 0) > 0 and hits.get("P10", 0) > 0, str({k: hits.get(k) for k in ("P09", "P10")}))

        # Zone server isolieren: Patientenportal fällt freundlich aus
        hub_json("POST", "/api/isolate/server")
        pr = hub_py("""
import requests
r = requests.post('http://127.0.0.1:8080/via/gast-client/patientenportal/login', data={'pid': 'P-1001', 'pin': '1234'}, allow_redirects=False)
print(r.status_code, 'Gerade nicht erreichbar' in r.text)
""").stdout.split()
        check("Zone server isoliert: Patientenportal zeigt Hinweisseite statt Fehler", pr[:2] == ["503", "True"], str(pr))
        hub_json("POST", "/api/release/server")
        pr = hub_py("""
import requests
r = requests.post('http://127.0.0.1:8080/via/gast-client/patientenportal/login', data={'pid': 'P-1001', 'pin': '1234'}, allow_redirects=False)
print(r.status_code)
""").stdout.split()
        check("Nach Freigabe funktioniert die Anmeldung wieder", pr[:1] == ["303"], str(pr))

        # Backup und Ransomware über das Portal
        def bk(action, body=None):
            code = (f"import requests,json;r=requests.post('http://127.0.0.1:8080/api/backup/{action}',json={body or {}!r},timeout=20);"
                    "print(json.dumps({'status':r.status_code,'body':r.json()}))")
            return json.loads(hub_py(code).stdout)
        st0 = hub_json("GET", "/api/backup/status")["body"]
        check("Backup-Seite: KIS hat Start-Backup, Daten nicht gesperrt", len(st0["backups"]) >= 1 and st0["locked"] is False)
        met = hub_py("import requests;print(requests.get('http://127.0.0.1:8080/metrics').text)").stdout
        check("Metriken lab_backup_age_seconds und lab_kis_locked vorhanden", "lab_backup_age_seconds" in met and "lab_kis_locked 0" in met)
        bk("run")
        r = bk("ransom")
        check("Ransomware-Simulation über das Portal", r["status"] == 200 and r["body"]["gesperrt"] is True)
        met = hub_py("import requests;print(requests.get('http://127.0.0.1:8080/metrics', timeout=10).text)").stdout
        check("Metrik lab_kis_locked springt auf 1 (löst Alarm KisDatenGesperrt aus)", "lab_kis_locked 1" in met)
        r = bk("restore")
        check("Wiederherstellung über das Portal", r["status"] == 200 and r["body"]["dauer_ms"] >= 0, str(r))
        met = hub_py("import requests;print(requests.get('http://127.0.0.1:8080/metrics', timeout=10).text)").stdout
        check("Nach der Wiederherstellung ist lab_kis_locked wieder 0", "lab_kis_locked 0" in met)
    finally:
        cleanup()

    failed = [r for r in results if not r[1]]
    print(f"\n{len(results)-len(failed)} von {len(results)} Prüfungen bestanden.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
