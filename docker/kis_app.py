"""KIS im Klinikum-Lab: Verwaltungsoberfläche und schmale Schnittstelle für das Patientenportal.

Zwei Zugänge:
  * /staff/...        Weboberfläche für Mitarbeitende, mit Anmeldung und Rollen
  * /api/portal/...   Schnittstelle für das Patientenportal in der DMZ (nur mit Schlüssel im Header)

Zwei Ebenen schützen das KIS: Die Firewall entscheidet, wer es im Netz erreicht (Zone).
Die Rolle entscheidet, was jemand darin sehen und tun darf (Anwendung). Ärztin, Pflege, Empfang,
Abrechnung und IT-Administration sehen jeweils etwas anderes. Ärztin und Pflege sehen nur
Patienten mit Behandlungsbezug, die Ärztin kann im Notfall mit Begründung darüber hinaus (protokolliert).
Die IT-Administration sieht keine Patientendaten, nur das Protokoll.
"""
from __future__ import annotations

import json
import os
import secrets
import time
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, quote, urlparse

import clinic
from clinic import ABTEILUNGEN, ROLLEN, Conflict, Denied, Locked, NotFound, darf
from webui import datum, esc, euro, flash, jdump, page, parse_form, safe_prefix

PORTAL_KEY = os.environ.get("PORTAL_KEY", "portal-lab-key")
BRAND = "KIS · Verwaltung"
NAV = [("start", "Übersicht", "/staff", None), ("patienten", "Patienten", "/staff/patienten", "patienten"), ("termine", "Termine", "/staff/termine", "termine"),
       ("abrechnung", "Abrechnung", "/staff/abrechnung", "abrechnung"), ("archiv", "Archiv", "/staff/archiv", "archiv"), ("protokoll", "Protokoll", "/staff/protokoll", "protokoll")]
SESSION_S = 1800


def make_handler(store: clinic.Store, node_name: str = "kis", zone: str = "server", description: str = ""):
    sessions: dict[str, dict] = {}

    class KisHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *args):
            pass

        # ---------------- Hilfen ----------------
        @property
        def prefix(self) -> str:
            return safe_prefix(self.headers.get("X-Prefix"))

        def send_bytes(self, status: int, body: bytes, ctype: str = "text/html; charset=utf-8", extra: dict | None = None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def redirect(self, path: str, msg: str = "", err: bool = False):
            q = (f"?{'err' if err else 'msg'}=" + quote(msg)) if msg else ""
            self.send_bytes(303, b"", extra={"Location": self.prefix + path + q})

        def read_body(self) -> bytes:
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(min(n, 100_000)) if n else b""

        def session(self):
            c = self.headers.get("Cookie", "")
            sid = next((p.split("=", 1)[1] for p in (x.strip() for x in c.split(";")) if p.startswith("ksid=")), "")
            for k in [k for k, v in sessions.items() if v["exp"] < time.time()]:
                del sessions[k]
            s = sessions.get(sid)
            if s:
                s["exp"] = time.time() + SESSION_S
            return s

        def staff_page(self, active: str, title: str, body: str, status: int = 200, s: dict | None = None):
            banner = ""
            if store.locked:
                banner = "ACHTUNG: Die Daten sind verschlüsselt (Ransomware-Simulation). Das KIS ist im Notbetrieb. Wiederherstellung über das NetOps-Portal, Seite Backup."
            nav = [(k, label, path) for k, label, path, perm in NAV if s and (perm is None or darf(s["rolle"], perm))] if s else []
            if s:
                body += (f'<div class=card><span class=mute>Angemeldet als <b>{esc(s["name"])}</b>, Rolle {esc(ROLLEN[s["rolle"]]["titel"])}.</span> '
                         f'<form class=inline method=post action="{esc(self.prefix)}/staff/logout"><input type=hidden name=csrf value="{esc(s["csrf"])}"><button class=sec>Abmelden</button></form></div>')
            self.send_bytes(status, page(title, body, nav, self.prefix, active, BRAND, banner))

        def csrf(self, s: dict) -> str:
            return f'<input type=hidden name=csrf value="{esc(s["csrf"])}">'

        def need(self, s: dict, recht: str) -> bool:
            """Prüft die Rolle. Bei Verstoß: Meldung, Protokolleintrag, Status 403."""
            if darf(s["rolle"], recht):
                return True
            store.log(s["user"], f"VERWEIGERT: {recht} ({self.path.split('?')[0]}) für Rolle {s['rolle']}")
            self.staff_page("start", "Kein Zugriff", f'<div class="card"><h1>Kein Zugriff</h1><p class=bad>Ihre Rolle ({esc(ROLLEN[s["rolle"]]["titel"])}) hat dafür keine Berechtigung.</p>'
                            f'<p class=mute>Der Versuch wurde protokolliert.</p></div>', 403, s)
            return False

        def msgs(self, q: dict) -> str:
            return flash(q.get("msg", [None])[0]) + flash(q.get("err", [None])[0], err=True)

        def fail(self, exc: Exception, staff: bool = False, q: dict | None = None):
            code = {Locked: 503, NotFound: 404, Conflict: 409, Denied: 403}.get(type(exc), 500)
            if staff:
                self.staff_page("start", "Fehler", f'<div class="card"><h1>Das hat nicht geklappt</h1><p class="bad">{esc(exc)}</p></div>', code, self.session())
            else:
                self.send_bytes(code, jdump({"error": str(exc)}), "application/json; charset=utf-8")

        def portal_auth(self) -> bool:
            if self.headers.get("X-Portal-Key") != PORTAL_KEY:
                self.send_bytes(401, jdump({"error": "Schlüssel fehlt oder falsch"}), "application/json; charset=utf-8")
                return False
            return True

        # ---------------- GET ----------------
        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            p = u.path.rstrip("/") or "/"
            try:
                if p == "/healthz":
                    return self.send_bytes(200, jdump({"status": "ok", "locked": store.locked}), "application/json; charset=utf-8")
                if p == "/":
                    return self.redirect("/staff")
                if p == "/api":
                    # Ohne Anmeldung nur Zähler, nie Namen
                    return self.send_bytes(200, jdump({"host": node_name, "zone": zone, "gesperrt": store.locked, **store.status()["zaehler"]}), "application/json; charset=utf-8")
                if p.startswith("/api/portal"):
                    return self.portal_get(p, q)
                if p.startswith("/staff"):
                    return self.staff_get(p, q)
                self.send_bytes(404, b"Nicht gefunden", "text/plain; charset=utf-8")
            except (Locked, NotFound, Conflict, Denied) as exc:
                self.fail(exc, staff=p.startswith("/staff"), q=q)

        # ---------------- POST ----------------
        def do_POST(self):
            u = urlparse(self.path)
            p = u.path.rstrip("/")
            raw = self.read_body()
            try:
                if p.startswith("/api/portal"):
                    return self.portal_post(p, raw)
                if p.startswith("/staff"):
                    return self.staff_post(p, parse_form(raw))
                self.send_bytes(404, b"Nicht gefunden", "text/plain; charset=utf-8")
            except (Locked, NotFound, Conflict, Denied) as exc:
                if p.startswith("/staff"):
                    # Fehler als Meldung auf der Zielseite statt leerer Fehlerseite
                    back = {"/staff/termine/neu": "/staff/termine", "/staff/termine/absagen": "/staff/termine",
                            "/staff/abrechnung/bezahlt": "/staff/abrechnung", "/staff/abrechnung/neu": "/staff/abrechnung", "/staff/login": "/staff/login"}.get(p, "/staff")
                    return self.redirect(back, str(exc), err=True)
                self.fail(exc)

        # ---------------- Portal-Schnittstelle ----------------
        def portal_get(self, p: str, q: dict):
            if not self.portal_auth():
                return
            pid = q.get("pid", [""])[0]
            if p == "/api/portal/akte":
                data = store.akte(pid)
            elif p == "/api/portal/termine":
                data = {"termine": store.termine(pid)}
            elif p == "/api/portal/zeiten":
                data = {"zeiten": store.freie_zeiten(q.get("abteilung", [""])[0], q.get("datum", [""])[0])}
            elif p == "/api/portal/rechnungen":
                data = {"rechnungen": store.rechnungen(pid)}
            elif p == "/api/portal/archiv":
                data = {"archiv": store.archiv(pid)}
            elif p == "/api/portal/archiv/dok":
                data = store.archiv_dok(q.get("id", [""])[0], pid)
            elif p == "/api/portal/abteilungen":
                data = {"abteilungen": ABTEILUNGEN, "zeiten": clinic.ZEITEN}
            else:
                return self.send_bytes(404, jdump({"error": "unbekannt"}), "application/json; charset=utf-8")
            self.send_bytes(200, jdump(data), "application/json; charset=utf-8")

        def portal_post(self, p: str, raw: bytes):
            if not self.portal_auth():
                return
            try:
                body = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                return self.send_bytes(400, jdump({"error": "kein gültiges JSON"}), "application/json; charset=utf-8")
            if p == "/api/portal/login":
                data = store.login(str(body.get("pid", "")), str(body.get("pin", "")))
            elif p == "/api/portal/termine/neu":
                data = store.termin_neu(str(body.get("pid", "")), str(body.get("abteilung", "")), str(body.get("datum", "")), str(body.get("zeit", "")))
            elif p == "/api/portal/termine/absagen":
                data = store.termin_absagen(str(body.get("id", "")), str(body.get("pid", "")))
            else:
                return self.send_bytes(404, jdump({"error": "unbekannt"}), "application/json; charset=utf-8")
            self.send_bytes(200, jdump(data), "application/json; charset=utf-8")

        # ---------------- Verwaltungsoberfläche (mit Anmeldung und Rollen) ----------------
        def login_page(self, m: str = ""):
            rows = "".join(f"<tr><td><code>{esc(u)}</code></td><td>{esc(ROLLEN[d['rolle']]['titel'])}</td><td><code>{esc(pw)}</code></td></tr>"
                           for u, d, pw in [(u, d, clinic._BENUTZER[u]["pw"]) for u, d in store.users.items()])
            body = (f'{m}<div class=card style="max-width:30rem;margin:1.5rem auto"><h1>Anmeldung Mitarbeitende</h1>'
                    f'<form method=post action="{esc(self.prefix)}/staff/login" class=row style="flex-direction:column;align-items:stretch">'
                    '<label>Benutzer<input name=user required autocomplete=username></label><label>Kennwort<input name=pw type=password required autocomplete=current-password></label><button>Anmelden</button></form></div>'
                    f'<div class=card style="max-width:30rem;margin:0 auto"><h2>Lab-Benutzer</h2><table><tr><th>Benutzer</th><th>Rolle</th><th>Kennwort</th></tr>{rows}</table>'
                    '<p class=mute>Nur im Lab sichtbar. Im Klinikum läuft die Anmeldung über den Verzeichnisdienst, mit Mehr-Faktor.</p></div>')
            self.staff_page("start", "Anmeldung", body)

        def staff_get(self, p: str, q: dict):
            m = self.msgs(q)
            if p == "/staff/login":
                return self.login_page(m)
            s = self.session()
            if not s:
                return self.redirect("/staff/login")
            if p == "/staff":
                zt = store.status()["zaehler"]
                if darf(s["rolle"], "patienten"):
                    pats = [x for x in store.patienten() if not ROLLEN[s["rolle"]]["bezug"] or x["id"] in s["bezug"]]
                else:
                    pats = None
                cards = ""
                if pats is not None:
                    cards += f'<div class=card><div class=big>{len(pats)}</div>{"Patienten in Ihrer Betreuung" if ROLLEN[s["rolle"]]["bezug"] else "Patienten"}</div>'
                if darf(s["rolle"], "termine"):
                    n = len([t for t in store.termine() if t["status"] == "geplant" and (not ROLLEN[s["rolle"]]["bezug"] or t["pid"] in s["bezug"])])
                    cards += f'<div class=card><div class=big>{n}</div>geplante Termine</div>'
                if darf(s["rolle"], "abrechnung"):
                    offen = [r for r in store.rechnungen() if r["status"] != "bezahlt"]
                    cards += f'<div class=card><div class=big>{len(offen)}</div>offene Rechnungen<br><span class=mute>{euro(sum(r["summe"] for r in offen))}</span></div>'
                if darf(s["rolle"], "archiv"):
                    cards += f'<div class=card><div class=big>{zt["archiv"]}</div>Archivdokumente</div>'
                if darf(s["rolle"], "protokoll"):
                    cards += f'<div class=card><div class=big>{len(store.audit)}</div>Protokolleinträge</div>'
                rechte = ", ".join(sorted(ROLLEN[s["rolle"]]["rechte"]))
                body = (f"{m}<h1>Guten Tag, {esc(s['name'])}</h1><div class=grid>{cards}</div>"
                        f'<div class=card><b>{esc(node_name)}</b> in Zone <b>{esc(zone)}</b>. Ihre Rolle: <b>{esc(ROLLEN[s["rolle"]]["titel"])}</b>.<br>'
                        f'<span class=mute>Rechte: {esc(rechte)}. Netz (Firewall) und Rolle (Anwendung) sind zwei getrennte Schutzebenen.</span></div>')
                return self.staff_page("start", "Übersicht", body, 200, s)
            if p == "/staff/patienten":
                if not self.need(s, "patienten"):
                    return
                bezug = ROLLEN[s["rolle"]]["bezug"]
                akte_link = darf(s["rolle"], "akte")
                rows = ""
                for x in store.patienten():
                    if bezug and x["id"] not in s["bezug"]:
                        continue
                    pid = f'<a href="{esc(self.prefix)}/staff/patient?id={esc(x["id"])}">{esc(x["id"])}</a>' if akte_link else esc(x["id"])
                    rows += f'<tr><td>{pid}</td><td>{esc(x["name"])}</td><td>{datum(x["geboren"])}</td><td>{esc(x["versicherung"])}</td><td>{esc(x["station"])}</td></tr>'
                hint = ""
                if bezug:
                    nf = ""
                    if ROLLEN[s["rolle"]]["notfall"]:
                        nf = (f'<form method=post action="{esc(self.prefix)}/staff/notfall" class=row>{self.csrf(s)}<label>Patientennummer<input name=pid required placeholder="P-1002"></label>'
                              f'<label>Begründung<input name=grund required minlength=8 size=32></label><button class=sec>Notfallzugriff</button></form>')
                    hint = (f'<div class=card><h2>Ohne Behandlungsbezug</h2><p class=mute>Sie sehen nur Patienten, die Sie betreuen. '
                            f'{"Im Notfall dürfen Sie mit Begründung eine fremde Akte öffnen. Das wird protokolliert und nachträglich geprüft." if nf else "Ein Notfallzugriff ist für Ihre Rolle nicht vorgesehen."}</p>{nf}</div>')
                body = (f"{m}<h1>Patienten</h1><div class=card><table><tr><th>Nr.</th><th>Name</th><th>Geboren</th><th>Versicherung</th><th>Station</th></tr>{rows}</table>"
                        f'{"" if akte_link else "<p class=mute>Ihre Rolle sieht nur Stammdaten, keine medizinische Akte.</p>"}</div>{hint}')
                return self.staff_page("patienten", "Patienten", body, 200, s)
            if p == "/staff/patient":
                if not self.need(s, "akte"):
                    return
                pid = q.get("id", [""])[0]
                if ROLLEN[s["rolle"]]["bezug"] and pid not in s["bezug"] and pid not in s.setdefault("notfall", set()):
                    store.log(s["user"], f"VERWEIGERT: Akte {pid} ohne Behandlungsbezug")
                    body = (f'<div class=card><h1>Kein Behandlungsbezug</h1><p class=bad>Sie betreuen diesen Patienten nicht.</p>'
                            f'<p class=mute>Der Versuch wurde protokolliert. {"Im Notfall: Seite Patienten, Notfallzugriff mit Begründung." if ROLLEN[s["rolle"]]["notfall"] else ""}</p></div>')
                    return self.staff_page("patienten", "Kein Zugriff", body, 403, s)
                a = store.akte(pid, who=s["user"])
                pa = a["patient"]
                diag = "".join(f"<tr><td>{datum(d['datum'])}</td><td>{esc(d['icd'])}</td><td>{esc(d['text'])}</td></tr>" for d in a["diagnosen"])
                med = "".join(f"<tr><td>{esc(d['name'])}</td><td>{esc(d['dosis'])}</td><td>seit {datum(d['seit'])}</td></tr>" for d in a["medikation"])
                bef = "".join(f"<tr><td>{datum(d['datum'])}</td><td>{esc(d['typ'])}</td><td>{esc(d['ergebnis'])}</td></tr>" for d in a["befunde"])
                bef_card = (f"<div class=card><h2>Befunde</h2><table>{bef or '<tr><td class=mute>keine</td></tr>'}</table></div>" if darf(s["rolle"], "akte_befunde")
                            else '<div class=card><h2>Befunde</h2><p class=mute>Für Ihre Rolle nicht sichtbar (nur ärztlicher Dienst).</p></div>')
                body = (f"<h1>{esc(pa['name'])} <span class=mute>({esc(pa['id'])})</span></h1>"
                        f"<div class=card>Geboren {datum(pa['geboren'])} · {esc(pa['versicherung'])} · Station {esc(pa['station'])}<br>"
                        f"<span class=mute>Jeder Aktenzugriff wird mit Ihrem Namen protokolliert.</span></div>"
                        f"<div class=card><h2>Diagnosen</h2><table>{diag or '<tr><td class=mute>keine</td></tr>'}</table></div>"
                        f"<div class=card><h2>Medikation</h2><table>{med or '<tr><td class=mute>keine</td></tr>'}</table></div>{bef_card}")
                return self.staff_page("patienten", pa["name"], body, 200, s)
            if p == "/staff/termine":
                if not self.need(s, "termine"):
                    return
                bezug = ROLLEN[s["rolle"]]["bezug"]
                aendern = darf(s["rolle"], "termine_aendern")
                names = {x["id"]: x["name"] for x in store.patienten()}
                form = ""
                if aendern:
                    opts = "".join(f'<option value="{esc(i)}">{esc(i)} {esc(n)}</option>' for i, n in names.items())
                    abt = "".join(f"<option>{esc(a)}</option>" for a in ABTEILUNGEN)
                    zeiten = "".join(f"<option>{z}</option>" for z in clinic.ZEITEN)
                    form = (f"<div class=card><h2>Neuer Termin</h2><form method=post action=\"{esc(self.prefix)}/staff/termine/neu\" class=row>{self.csrf(s)}"
                            f"<label>Patient<select name=pid>{opts}</select></label><label>Abteilung<select name=abteilung>{abt}</select></label>"
                            f"<label>Datum<input type=date name=datum required></label><label>Zeit<select name=zeit>{zeiten}</select></label><button>Anlegen</button></form></div>")
                rows = ""
                for t in store.termine():
                    if bezug and t["pid"] not in s["bezug"]:
                        continue
                    act = (f'<form class=inline method=post action="{esc(self.prefix)}/staff/termine/absagen">{self.csrf(s)}<input type=hidden name=id value="{esc(t["id"])}"><button class=sec>Absagen</button></form>'
                           if aendern and t["status"] == "geplant" else "")
                    cls = {"geplant": "ok", "abgesagt": "bad"}.get(t["status"], "mute")
                    rows += (f'<tr><td>{esc(t["id"])}</td><td>{datum(t["datum"])} {esc(t["zeit"])}</td><td>{esc(names.get(t["pid"], t["pid"]))}</td>'
                             f'<td>{esc(t["abteilung"])}</td><td class={cls}>{esc(t["status"])}</td><td>{act}</td></tr>')
                note = "" if aendern else '<p class=mute>Ihre Rolle darf Termine ansehen, aber nicht ändern.</p>'
                body = f"{m}<h1>Termine</h1>{form}<div class=card><table><tr><th>Nr.</th><th>Wann</th><th>Patient</th><th>Abteilung</th><th>Status</th><th></th></tr>{rows}</table>{note}</div>"
                return self.staff_page("termine", "Termine", body, 200, s)
            if p == "/staff/abrechnung":
                if not self.need(s, "abrechnung"):
                    return
                aendern = darf(s["rolle"], "abrechnung_aendern")
                names = {x["id"]: x["name"] for x in store.patienten()}
                rech = store.rechnungen()
                form = ""
                if aendern:
                    opts = "".join(f'<option value="{esc(i)}">{esc(i)} {esc(n)}</option>' for i, n in names.items())
                    form = (f"<div class=card><h2>Rechnung erstellen</h2><form method=post action=\"{esc(self.prefix)}/staff/abrechnung/neu\" class=row>{self.csrf(s)}"
                            f"<label>Patient<select name=pid>{opts}</select></label><label>Leistung<input name=text required maxlength=80></label>"
                            f"<label>Betrag in Euro<input name=betrag type=number step=0.01 min=0.01 required></label><button>Erstellen</button></form></div>")
                rows = ""
                for r in rech:
                    act = (f'<form class=inline method=post action="{esc(self.prefix)}/staff/abrechnung/bezahlt">{self.csrf(s)}<input type=hidden name=id value="{esc(r["id"])}"><button class=sec>Als bezahlt buchen</button></form>'
                           if aendern and r["status"] != "bezahlt" else "")
                    pos = "<br>".join(f"{esc(x['text'])}: {euro(x['betrag'])}" for x in r["positionen"])
                    rows += (f'<tr><td>{esc(r["id"])}</td><td>{esc(names.get(r["pid"], r["pid"]))}</td><td class=mute>{pos}</td><td><b>{euro(r["summe"])}</b></td>'
                             f'<td>{datum(r["faellig"])}</td><td class={"ok" if r["status"] == "bezahlt" else "warn"}>{esc(r["status"])}</td><td>{act}</td></tr>')
                offen = sum(r["summe"] for r in rech if r["status"] != "bezahlt")
                body = (f"{m}<h1>Abrechnung</h1><div class=card><b>Offen: {euro(offen)}</b><br><span class=mute>Die Abrechnung sieht Leistungen und Beträge, keine Diagnosen.</span></div>{form}"
                        f"<div class=card><table><tr><th>Nr.</th><th>Patient</th><th>Positionen</th><th>Summe</th><th>Fällig</th><th>Status</th><th></th></tr>{rows}</table></div>")
                return self.staff_page("abrechnung", "Abrechnung", body, 200, s)
            if p == "/staff/archiv":
                if not self.need(s, "archiv"):
                    return
                bezug = ROLLEN[s["rolle"]]["bezug"]
                names = {x["id"]: x["name"] for x in store.patienten()}
                rows = "".join(f'<tr><td><a href="{esc(self.prefix)}/staff/archiv/dok?id={esc(a["id"])}">{esc(a["id"])}</a></td><td>{esc(a["titel"])}</td>'
                               f'<td>{esc(names.get(a["pid"], a["pid"]))}</td><td>{esc(a["typ"])}, {a["jahr"]}</td><td>{a["kb"]} KB</td></tr>'
                               for a in store.archiv() if not bezug or a["pid"] in s["bezug"])
                body = (f"{m}<h1>Archiv</h1><div class=card><table><tr><th>Nr.</th><th>Titel</th><th>Patient</th><th>Art, Jahr</th><th>Größe</th></tr>{rows}</table>"
                        f"<p class=mute>Archivierte Dokumente bleiben nach den gesetzlichen Fristen aufbewahrt. Im Lab nur Beispieltexte.</p></div>")
                return self.staff_page("archiv", "Archiv", body, 200, s)
            if p == "/staff/archiv/dok":
                if not self.need(s, "archiv"):
                    return
                aid = q.get("id", [""])[0]
                d = store.archiv_dok(aid, None, who=s["user"])
                if ROLLEN[s["rolle"]]["bezug"] and d["pid"] not in s["bezug"]:
                    store.log(s["user"], f"VERWEIGERT: Archivdokument {aid} ohne Behandlungsbezug")
                    return self.staff_page("archiv", "Kein Zugriff", '<div class=card><h1>Kein Behandlungsbezug</h1><p class=bad>Das Dokument gehört zu einem Patienten, den Sie nicht betreuen.</p></div>', 403, s)
                body = f'<h1>{esc(d["titel"])}</h1><div class=card><span class=mute>{esc(d["id"])} · {esc(d["typ"])} · {d["jahr"]}</span><p>{esc(d["text"])}</p></div>'
                return self.staff_page("archiv", d["titel"], body, 200, s)
            if p == "/staff/protokoll":
                if not self.need(s, "protokoll"):
                    return
                rows = "".join(f"<tr><td>{esc(a['t'])}</td><td>{esc(a['who'])}</td><td>{esc(a['action'])}</td></tr>" for a in reversed(store.audit[-80:]))
                body = f"<h1>Protokoll</h1><div class=card><p class=mute>Wer hat wann was getan, auch verweigerte Zugriffe und Notfallzugriffe.</p><table><tr><th>Zeit</th><th>Wer</th><th>Aktion</th></tr>{rows}</table></div>"
                return self.staff_page("protokoll", "Protokoll", body, 200, s)
            self.send_bytes(404, b"Nicht gefunden", "text/plain; charset=utf-8")

        def staff_post(self, p: str, f: dict):
            if p == "/staff/login":
                try:
                    who = store.staff_login(f.get("user", "").strip(), f.get("pw", ""))
                except Denied as exc:
                    return self.redirect("/staff/login", str(exc), err=True)
                sid = secrets.token_urlsafe(24)
                sessions[sid] = {**who, "csrf": secrets.token_urlsafe(16), "exp": time.time() + SESSION_S, "notfall": set(), "sid": sid}
                return self.send_bytes(303, b"", extra={"Location": self.prefix + "/staff", "Set-Cookie": f"ksid={sid}; Path={self.prefix or '/'}; HttpOnly; SameSite=Lax; Max-Age={SESSION_S}"})
            s = self.session()
            if not s:
                return self.redirect("/staff/login")
            if not secrets.compare_digest(f.get("csrf", ""), s["csrf"]):
                store.log(s["user"], "VERWEIGERT: ungültiger CSRF-Schlüssel")
                return self.staff_page("start", "Abgelehnt", '<div class=card><p class=bad>Die Anfrage wurde abgelehnt (Sicherheitsprüfung).</p></div>', 403, s)
            if p == "/staff/logout":
                sessions.pop(s["sid"], None)
                store.log(s["user"], "Abmeldung")
                return self.send_bytes(303, b"", extra={"Location": self.prefix + "/staff/login", "Set-Cookie": f"ksid=; Path={self.prefix or '/'}; Max-Age=0"})
            if p == "/staff/notfall":
                if not ROLLEN[s["rolle"]]["notfall"]:
                    store.log(s["user"], "VERWEIGERT: Notfallzugriff für Rolle " + s["rolle"])
                    return self.staff_page("start", "Kein Zugriff", '<div class=card><h1>Kein Zugriff</h1><p class=bad>Ihre Rolle darf keinen Notfallzugriff nutzen.</p></div>', 403, s)
                pid = f.get("pid", "").strip()
                store.notfallzugriff(s["user"], pid, f.get("grund", ""))
                s["notfall"].add(pid)
                return self.send_bytes(303, b"", extra={"Location": f"{self.prefix}/staff/patient?id={quote(pid)}"})
            if p in ("/staff/termine/neu", "/staff/termine/absagen"):
                if not self.need(s, "termine_aendern"):
                    return
                if p.endswith("neu"):
                    t = store.termin_neu(f.get("pid", ""), f.get("abteilung", ""), f.get("datum", ""), f.get("zeit", ""), who=s["user"])
                    return self.redirect("/staff/termine", f"Termin {t['id']} angelegt")
                t = store.termin_absagen(f.get("id", ""), None, who=s["user"])
                return self.redirect("/staff/termine", f"Termin {t['id']} abgesagt")
            if p in ("/staff/abrechnung/bezahlt", "/staff/abrechnung/neu"):
                if not self.need(s, "abrechnung_aendern"):
                    return
                if p.endswith("bezahlt"):
                    r = store.rechnung_bezahlt(f.get("id", ""), who=s["user"])
                    return self.redirect("/staff/abrechnung", f"{r['id']} als bezahlt gebucht")
                try:
                    betrag = float(f.get("betrag", "0").replace(",", "."))
                except ValueError:
                    raise Conflict("Betrag ist keine Zahl")
                r = store.rechnung_neu(f.get("pid", ""), f.get("text", ""), betrag, who=s["user"])
                return self.redirect("/staff/abrechnung", f"Rechnung {r['id']} erstellt")
            self.send_bytes(404, b"Nicht gefunden", "text/plain; charset=utf-8")

    return KisHandler
