"""Patientenportal in der DMZ.

Der Patient meldet sich mit Patientennummer und PIN an und sieht nur seine eigenen Daten:
Akte, Termine (buchen und absagen), Rechnungen und Archiv.

Das Portal hält selbst keine Patientendaten. Es fragt bei jeder Seite das KIS (Zone Server,
tcp/8080, Regel P10). Zur Datenbank hat die DMZ keinen Zugang. Fällt das KIS aus oder ist
die Zone isoliert, zeigt das Portal eine freundliche Hinweisseite.

Sicherheit im Kleinen: zufällige Sitzungs-ID im Cookie (HttpOnly, SameSite), Ablauf nach
15 Minuten, CSRF-Schlüssel bei jedem Formular, Sperre nach Fehlversuchen (im KIS),
keine Cache-Speicherung, strikte Content-Security-Policy.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.request
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, quote, urlencode, urlparse

from webui import datum, esc, euro, flash, page, parse_form, safe_prefix

KIS_URL = os.environ.get("KIS_URL", "http://10.10.20.10:8080")
PORTAL_KEY = os.environ.get("PORTAL_KEY", "portal-lab-key")
SESSION_S = int(os.environ.get("SESSION_SECONDS", "900"))
BRAND = "Patientenportal"
NAV = [("start", "Übersicht", "/"), ("akte", "Meine Akte", "/akte"), ("termine", "Termine", "/termine"),
       ("rechnungen", "Rechnungen", "/rechnungen"), ("archiv", "Archiv", "/archiv")]


class KisDown(Exception):
    pass


class KisError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def kis_call(method: str, path: str, payload: dict | None = None, query: dict | None = None) -> dict:
    url = KIS_URL + path + (("?" + urlencode(query)) if query else "")
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"X-Portal-Key": PORTAL_KEY, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            msg = json.loads(exc.read().decode()).get("error", "Fehler")
        except (ValueError, OSError):
            msg = "Fehler"
        if exc.code == 503:
            raise KisDown(msg) from exc
        raise KisError(exc.code, msg) from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise KisDown(str(exc)) from exc


def make_handler():
    sessions: dict[str, dict] = {}
    lock = threading.Lock()

    class PatientHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *args):
            pass

        @property
        def prefix(self) -> str:
            return safe_prefix(self.headers.get("X-Prefix"))

        def cookie_path(self) -> str:
            return self.prefix or "/"

        def session(self) -> dict | None:
            c = SimpleCookie(self.headers.get("Cookie", ""))
            sid = c["sid"].value if "sid" in c else None
            with lock:
                for k in [k for k, v in sessions.items() if v["exp"] < time.time()]:
                    del sessions[k]
                s = sessions.get(sid or "")
                if s:
                    s["exp"] = time.time() + SESSION_S
                return s

        def send(self, status: int, body: bytes, extra: list[tuple[str, str]] | None = None):
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
            for k, v in extra or []:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def redirect(self, path: str, msg: str = "", err: bool = False, extra=None):
            q = (f"?{'err' if err else 'msg'}=" + quote(msg)) if msg else ""
            self.send(303, b"", [("Location", self.prefix + path + q)] + (extra or []))

        def view(self, s: dict | None, active: str, title: str, body: str, status: int = 200, extra=None):
            nav = NAV if s else []
            tail = ""
            if s:
                tail = (f'<div class=card><span class=mute>Angemeldet als {esc(s["name"])} ({esc(s["pid"])}).</span> '
                        f'<form class=inline method=post action="{esc(self.prefix)}/logout"><input type=hidden name=csrf value="{esc(s["csrf"])}"><button class=sec>Abmelden</button></form></div>')
            self.send(status, page(title, body + tail, nav, self.prefix, active, BRAND), extra)

        def down(self, s, exc: Exception):
            body = ('<div class=card><h1>Gerade nicht erreichbar</h1><p>Das Patientenportal kann im Moment nicht auf die Klinikdaten zugreifen. '
                    'Bitte versuchen Sie es später noch einmal. Ihre Daten sind sicher.</p>'
                    f'<p class=mute>Technischer Hinweis (Lab): {esc(exc)}</p></div>')
            self.view(s, "start", "Nicht erreichbar", body, 503)

        # ---------------- GET ----------------
        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            p = u.path.rstrip("/") or "/"
            s = self.session()
            m = flash(q.get("msg", [None])[0]) + flash(q.get("err", [None])[0], err=True)
            if p == "/healthz":
                return self.send(200, b"ok")
            if p == "/login" or (p == "/" and not s):
                return self.view(None, "start", "Anmelden", self.login_form(m))
            if not s:
                return self.redirect("/login")
            try:
                if p == "/":
                    return self.home(s, m)
                if p == "/akte":
                    return self.akte(s, m)
                if p == "/termine":
                    return self.termine(s, m)
                if p == "/rechnungen":
                    return self.rechnungen(s, m)
                if p == "/archiv":
                    return self.archiv(s, m)
                if p == "/archiv/dok":
                    return self.dok(s, q.get("id", [""])[0])
            except KisDown as exc:
                return self.down(s, exc)
            except KisError as exc:
                return self.view(s, "start", "Fehler", f'<div class=card><p class=bad>{esc(exc)}</p></div>', exc.status)
            self.send(404, page("Nicht gefunden", "<div class=card>Seite nicht gefunden.</div>", NAV, self.prefix, "", BRAND))

        # ---------------- POST ----------------
        def do_POST(self):
            u = urlparse(self.path)
            p = u.path.rstrip("/")
            n = int(self.headers.get("Content-Length") or 0)
            f = parse_form(self.rfile.read(min(n, 20_000)) if n else b"")
            if p == "/login":
                return self.do_login(f)
            s = self.session()
            if not s:
                return self.redirect("/login")
            if not secrets.compare_digest(f.get("csrf", ""), s["csrf"]):
                return self.view(s, "start", "Abgelehnt", '<div class=card><p class=bad>Die Anfrage wurde abgelehnt (Sicherheitsprüfung).</p></div>', 403)
            try:
                if p == "/logout":
                    with lock:
                        sessions.pop(s["sid"], None)
                    return self.redirect("/login", "Sie wurden abgemeldet.", extra=[("Set-Cookie", self.cookie("", 0))])
                if p == "/termine/neu":
                    t = kis_call("POST", "/api/portal/termine/neu", {"pid": s["pid"], "abteilung": f.get("abteilung", ""), "datum": f.get("datum", ""), "zeit": f.get("zeit", "")})
                    return self.redirect("/termine", f"Termin gebucht: {datum(t['datum'])}, {t['zeit']} Uhr, {t['abteilung']}")
                if p == "/termine/absagen":
                    t = kis_call("POST", "/api/portal/termine/absagen", {"pid": s["pid"], "id": f.get("id", "")})
                    return self.redirect("/termine", f"Termin {t['id']} abgesagt")
            except KisDown as exc:
                return self.down(s, exc)
            except KisError as exc:
                return self.redirect("/termine", str(exc), err=True)
            self.send(404, b"Nicht gefunden")

        # ---------------- Sitzung ----------------
        def cookie(self, sid: str, max_age: int) -> str:
            return f"sid={sid}; Path={self.cookie_path()}; HttpOnly; SameSite=Lax; Max-Age={max_age}"

        def login_form(self, m: str) -> str:
            return (f'{m}<div class=card style="max-width:26rem;margin:2rem auto"><h1>Anmelden</h1>'
                    f'<form method=post action="{esc(self.prefix)}/login" class=row style="flex-direction:column;align-items:stretch">'
                    '<label>Patientennummer<input name=pid required autocomplete=username placeholder="P-1001"></label>'
                    '<label>PIN<input name=pin type=password required autocomplete=current-password></label><button>Anmelden</button></form>'
                    '<p class=mute>Lab-Zugangsdaten (erfundene Personen): P-1001 / 1234, P-1002 / 2345, P-1003 / 3456.</p></div>')

        def do_login(self, f: dict):
            try:
                who = kis_call("POST", "/api/portal/login", {"pid": f.get("pid", "").strip(), "pin": f.get("pin", "")})
            except KisDown as exc:
                return self.down(None, exc)
            except KisError as exc:
                return self.redirect("/login", str(exc), err=True)
            sid = secrets.token_urlsafe(24)
            with lock:
                sessions[sid] = {"sid": sid, "pid": who["pid"], "name": who["name"], "csrf": secrets.token_urlsafe(16), "exp": time.time() + SESSION_S}
            self.redirect("/", extra=[("Set-Cookie", self.cookie(sid, SESSION_S))])

        # ---------------- Seiten ----------------
        def home(self, s, m):
            t = [x for x in kis_call("GET", "/api/portal/termine", query={"pid": s["pid"]})["termine"] if x["status"] == "geplant"]
            r = [x for x in kis_call("GET", "/api/portal/rechnungen", query={"pid": s["pid"]})["rechnungen"] if x["status"] != "bezahlt"]
            nxt = f"{datum(t[0]['datum'])}, {esc(t[0]['zeit'])} Uhr, {esc(t[0]['abteilung'])}" if t else "kein Termin geplant"
            body = (f"{m}<h1>Guten Tag, {esc(s['name'])}</h1><div class=grid>"
                    f'<div class=card><h2>Nächster Termin</h2>{nxt}<br><a href="{esc(self.prefix)}/termine">Termine verwalten</a></div>'
                    f'<div class=card><h2>Offene Rechnungen</h2><span class=big>{len(r)}</span><br>{euro(sum(x["summe"] for x in r))}<br><a href="{esc(self.prefix)}/rechnungen">ansehen</a></div>'
                    f'<div class=card><h2>Meine Akte</h2>Diagnosen, Medikation, Befunde<br><a href="{esc(self.prefix)}/akte">öffnen</a></div></div>')
            self.view(s, "start", "Übersicht", body)

        def akte(self, s, m):
            a = kis_call("GET", "/api/portal/akte", query={"pid": s["pid"]})
            diag = "".join(f"<tr><td>{datum(d['datum'])}</td><td>{esc(d['text'])}</td></tr>" for d in a["diagnosen"])
            med = "".join(f"<tr><td>{esc(d['name'])}</td><td>{esc(d['dosis'])}</td></tr>" for d in a["medikation"])
            bef = "".join(f"<tr><td>{datum(d['datum'])}</td><td>{esc(d['typ'])}</td><td>{esc(d['ergebnis'])}</td></tr>" for d in a["befunde"])
            body = (f"{m}<h1>Meine Akte</h1><div class=card><h2>Diagnosen</h2><table>{diag or '<tr><td class=mute>keine</td></tr>'}</table></div>"
                    f"<div class=card><h2>Medikation</h2><table>{med or '<tr><td class=mute>keine</td></tr>'}</table></div>"
                    f"<div class=card><h2>Befunde</h2><table>{bef or '<tr><td class=mute>keine</td></tr>'}</table></div>"
                    "<p class=mute>Sie sehen nur Ihre eigenen Daten. Jeder Abruf wird im Klinikum protokolliert.</p>")
            self.view(s, "akte", "Meine Akte", body)

        def termine(self, s, m):
            t = kis_call("GET", "/api/portal/termine", query={"pid": s["pid"]})["termine"]
            cfg = kis_call("GET", "/api/portal/abteilungen")
            today = dt.date.today()
            tage = [(today + dt.timedelta(days=i)) for i in range(1, 15) if (today + dt.timedelta(days=i)).weekday() < 5]
            abt = "".join(f"<option>{esc(a)}</option>" for a in cfg["abteilungen"])
            dat = "".join(f'<option value="{d.isoformat()}">{d.strftime("%d.%m.%Y")}</option>' for d in tage)
            zeit = "".join(f"<option>{esc(z)}</option>" for z in cfg["zeiten"])
            rows = ""
            for x in t:
                act = (f'<form class=inline method=post action="{esc(self.prefix)}/termine/absagen"><input type=hidden name=csrf value="{esc(s["csrf"])}">'
                       f'<input type=hidden name=id value="{esc(x["id"])}"><button class=sec>Absagen</button></form>') if x["status"] == "geplant" else ""
                cls = {"geplant": "ok", "abgesagt": "bad"}.get(x["status"], "mute")
                rows += f'<tr><td>{datum(x["datum"])} {esc(x["zeit"])}</td><td>{esc(x["abteilung"])}</td><td class={cls}>{esc(x["status"])}</td><td>{act}</td></tr>'
            body = (f'{m}<h1>Termine</h1><div class=card><h2>Neuen Termin buchen</h2><form method=post action="{esc(self.prefix)}/termine/neu" class=row>'
                    f'<input type=hidden name=csrf value="{esc(s["csrf"])}"><label>Abteilung<select name=abteilung>{abt}</select></label>'
                    f'<label>Datum<select name=datum>{dat}</select></label><label>Uhrzeit<select name=zeit>{zeit}</select></label><button>Buchen</button></form>'
                    f'<p class=mute>Ist ein Termin schon vergeben, schlägt die Buchung mit einer Meldung fehl.</p></div>'
                    f'<div class=card><table><tr><th>Wann</th><th>Abteilung</th><th>Status</th><th></th></tr>{rows}</table></div>')
            self.view(s, "termine", "Termine", body)

        def rechnungen(self, s, m):
            r = kis_call("GET", "/api/portal/rechnungen", query={"pid": s["pid"]})["rechnungen"]
            rows = ""
            for x in r:
                pos = "<br>".join(f"{esc(p['text'])}: {euro(p['betrag'])}" for p in x["positionen"])
                cls = "ok" if x["status"] == "bezahlt" else "warn"
                rows += f'<tr><td>{esc(x["id"])}<br><span class=mute>{datum(x["datum"])}</span></td><td class=mute>{pos}</td><td><b>{euro(x["summe"])}</b></td><td>{datum(x["faellig"])}</td><td class={cls}>{esc(x["status"])}</td></tr>'
            body = (f"{m}<h1>Rechnungen</h1><div class=card><table><tr><th>Rechnung</th><th>Positionen</th><th>Summe</th><th>Fällig</th><th>Status</th></tr>"
                    f"{rows or '<tr><td class=mute>keine Rechnungen</td></tr>'}</table><p class=mute>Zahlungen bucht die Verwaltung. Im Lab gibt es keine Online-Zahlung.</p></div>")
            self.view(s, "rechnungen", "Rechnungen", body)

        def archiv(self, s, m):
            a = kis_call("GET", "/api/portal/archiv", query={"pid": s["pid"]})["archiv"]
            rows = "".join(f'<tr><td><a href="{esc(self.prefix)}/archiv/dok?id={esc(x["id"])}">{esc(x["titel"])}</a></td><td>{esc(x["typ"])}</td><td>{x["jahr"]}</td><td>{x["kb"]} KB</td></tr>' for x in a)
            body = f"{m}<h1>Archiv</h1><div class=card><table><tr><th>Dokument</th><th>Art</th><th>Jahr</th><th>Größe</th></tr>{rows or '<tr><td class=mute>keine Dokumente</td></tr>'}</table></div>"
            self.view(s, "archiv", "Archiv", body)

        def dok(self, s, aid: str):
            d = kis_call("GET", "/api/portal/archiv/dok", query={"pid": s["pid"], "id": aid})
            body = f'<h1>{esc(d["titel"])}</h1><div class=card><span class=mute>{esc(d["typ"])}, {d["jahr"]}</span><p>{esc(d["text"])}</p></div>'
            self.view(s, "archiv", d["titel"], body)

    return PatientHandler
