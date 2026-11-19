#!/usr/bin/env python3
"""Testet KIS und Patientenportal ohne Docker und ohne Firewall (nur auf localhost).

Prüft Anmeldung, Datentrennung, Termine, Rechnungen, Archiv, CSRF, Backup, Ransomware-Simulation
und Wiederherstellung. Start: python3 tools/app_test.py
"""
import datetime as dt
import http.cookiejar
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORTS = {"kis": 18080, "pp": 18081, "ag_kis": 17070, "ag_pp": 17071}
TOKEN = "testtoken"
RES = []


def check(name, cond, extra=""):
    RES.append(bool(cond))
    print(("  ok   " if cond else "  FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def spawn(name, services, extra_env):
    env = {**os.environ, "NODE_NAME": name, "NODE_ZONE": "test", "NODE_IP": "127.0.0.1", "NODE_BIND": "127.0.0.1",
           "NODE_TITLE": name, "NODE_DESCRIPTION": "Test", "SUPERNET": "127.0.0.0/8", "LAB_TOKEN": TOKEN,
           "NODE_SERVICES": json.dumps(services), "BACKUP_INTERVAL": "3600", "FETCH_PORTS": "80,8080,18080,18081", **extra_env}
    return subprocess.Popen([sys.executable, str(ROOT / "docker/node.py")], env=env, cwd=str(ROOT / "docker"))


def wait(port):
    for _ in range(60):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=0.5)
            return True
        except urllib.error.HTTPError:
            return True
        except OSError:
            time.sleep(0.2)
    return False


class NoRedir(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def browser():
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedir)

    def go(url, data=None, headers=None):
        req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode() if data is not None else None, headers=headers or {})
        try:
            r = op.open(req, timeout=5)
        except urllib.error.HTTPError as e:
            r = e
        return r.status if hasattr(r, "status") else r.code, r.read().decode(), dict(r.headers)
    return go, jar


def api(port, method, path, body=None, key="portal-lab-key"):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode() if body is not None else None, method=method,
                                 headers={"X-Portal-Key": key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def agent(port, method, path, body=None, token=TOKEN):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body or {}).encode() if method == "POST" else None, method=method,
                                 headers={"X-Lab-Token": token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def next_weekday(n):
    d = dt.date.today() + dt.timedelta(days=n)
    while d.weekday() >= 5:
        d += dt.timedelta(days=1)
    return d.isoformat()


def main():
    procs = [
        spawn("kis", [{"name": "kis-web", "port": PORTS["kis"], "kind": "http", "data": "kis", "title": "KIS"}], {"AGENT_PORT": str(PORTS["ag_kis"])}),
        spawn("patientenportal", [{"name": "portal-web", "port": PORTS["pp"], "kind": "http", "data": "patientportal", "title": "PP"}],
              {"AGENT_PORT": str(PORTS["ag_pp"]), "KIS_URL": f"http://127.0.0.1:{PORTS['kis']}"}),
    ]
    try:
        check("KIS und Patientenportal starten", wait(PORTS["kis"]) and wait(PORTS["pp"]) and wait(PORTS["ag_kis"]))
        pp = f"http://127.0.0.1:{PORTS['pp']}"
        kis = f"http://127.0.0.1:{PORTS['kis']}"

        print("Patientenportal")
        go, jar = browser()
        st, body, h = go(pp + "/")
        check("Startseite zeigt die Anmeldung", st == 200 and "Anmelden" in body)
        check("Sicherheitsheader gesetzt", "default-src 'none'" in h.get("Content-Security-Policy", "") and h.get("X-Frame-Options") == "DENY" and h.get("Cache-Control") == "no-store")
        st, body, h = go(pp + "/akte")
        check("Akte ohne Anmeldung leitet zur Anmeldung um", st == 303 and "/login" in h.get("Location", ""))
        st, body, h = go(pp + "/login", {"pid": "P-1001", "pin": "falsch"})
        check("Falsche PIN wird abgelehnt", st == 303 and "err=" in h.get("Location", ""))
        st, body, h = go(pp + "/login", {"pid": "P-1001", "pin": "1234"})
        cookie = h.get("Set-Cookie", "")
        check("Anmeldung klappt, Cookie ist HttpOnly und SameSite", st == 303 and "HttpOnly" in cookie and "SameSite=Lax" in cookie)
        st, body, h = go(pp + "/akte")
        check("Akte zeigt eigene Daten", st == 200 and "Bluthochdruck" in body and "MRT Knie" in body)
        check("Akte zeigt keine fremden Daten", "Knöchelfraktur" not in body and "Vorhofflimmern" not in body)
        st, body, h = go(pp + "/rechnungen")
        check("Rechnungen: eigene sichtbar, fremde nicht", "R-2026-0001" in body and "R-2026-0003" not in body and "336,90" in body)
        st, body, h = go(pp + "/archiv")
        check("Archiv: eigene Dokumente sichtbar, fremde nicht", "Entlassbrief" in body and "Aufnahmebogen" not in body)
        st, body, h = go(pp + "/archiv/dok?id=A-2018-0102")
        check("Fremdes Archivdokument wird verweigert", st == 403 and "gehört nicht" in body)
        st, body, h = go(pp + "/archiv/dok?id=A-2019-0007")
        check("Eigenes Archivdokument lässt sich lesen", st == 200 and "komplikationslos" in body)

        st, body, h = go(pp + "/termine")
        csrf = re.search(r'name="?csrf"? value="([^"]+)"', body).group(1)
        tag = next_weekday(2)
        st, body, h = go(pp + "/termine/neu", {"csrf": csrf, "abteilung": "Kardiologie", "datum": tag, "zeit": "14:30"})
        check("Termin buchen klappt", st == 303 and "msg=" in h.get("Location", ""), h.get("Location", ""))
        st, body, h = go(pp + "/termine")
        check("Gebuchter Termin erscheint in der Liste", "Kardiologie" in body and "geplant" in body)
        st, body, h = go(pp + "/termine/neu", {"csrf": csrf, "abteilung": "Kardiologie", "datum": tag, "zeit": "14:30"})
        check("Doppelbuchung wird abgelehnt", st == 303 and "err=" in h.get("Location", "") and "vergeben" in urllib.parse.unquote(h.get("Location", "")))
        st, body, h = go(pp + "/termine/neu", {"csrf": "falsch", "abteilung": "Kardiologie", "datum": tag, "zeit": "09:30"})
        check("Falscher CSRF-Schlüssel wird abgelehnt", st == 403)
        samstag = dt.date.today() + dt.timedelta(days=(5 - dt.date.today().weekday()) % 7 or 7)
        st, body, h = go(pp + "/termine/neu", {"csrf": csrf, "abteilung": "Kardiologie", "datum": samstag.isoformat(), "zeit": "09:30"})
        check("Wochenende wird abgelehnt", "err=" in h.get("Location", "") and "Wochenende" in urllib.parse.unquote(h.get("Location", "")))
        tid = [t for t in agent(PORTS["ag_kis"], "GET", "/kis/status")[1]["events"]][-1:]  # nur Aufruf
        st, data = api(PORTS["kis"], "GET", "/api/portal/termine?pid=P-1001")
        neu = [t for t in data["termine"] if t["zeit"] == "14:30" and t["abteilung"] == "Kardiologie"][0]
        st, body, h = go(pp + "/termine/absagen", {"csrf": csrf, "id": "T-0002"})
        check("Fremden Termin absagen wird verweigert", "err=" in h.get("Location", "") and "gehört nicht" in urllib.parse.unquote(h.get("Location", "")))
        st, body, h = go(pp + "/termine/absagen", {"csrf": csrf, "id": neu["id"]})
        check("Eigenen Termin absagen klappt", "msg=" in h.get("Location", ""))
        go2, _ = browser()
        for _ in range(5):
            go2(pp + "/login", {"pid": "P-1002", "pin": "0000"})
        st, body, h = go2(pp + "/login", {"pid": "P-1002", "pin": "2345"})
        check("Nach fünf Fehlversuchen ist das Konto kurz gesperrt", "err=" in h.get("Location", "") and "Fehlversuche" in urllib.parse.unquote(h.get("Location", "")))
        st, body, h = go(pp + "/logout", {"csrf": csrf})
        st, body, h = go(pp + "/akte")
        check("Nach dem Abmelden ist die Sitzung ungültig", st == 303)
        # Präfix (Betrieb hinter dem NetOps-Portal)
        go3, _ = browser()
        st, body, h = go3(pp + "/", headers={"X-Prefix": "/via/gast-client/patientenportal"})
        check("Links tragen den Präfix", 'action="/via/gast-client/patientenportal/login"' in body)
        st, body, h = go3(pp + "/login", {"pid": "P-1003", "pin": "3456"}, headers={"X-Prefix": "/via/x/y"})
        check("Cookie gilt nur für den Präfix-Pfad", "Path=/via/x/y" in h.get("Set-Cookie", ""))

        print("KIS Schnittstelle")
        st, _ = api(PORTS["kis"], "GET", "/api/portal/akte?pid=P-1001", key="falsch")
        check("Schnittstelle ohne Schlüssel wird abgelehnt", st == 401)
        st, body, h = browser()[0](kis + "/api")
        check("Offene Info-Seite nennt keine Namen", st == 200 and "Erika" not in body and "Mustermann" not in body)

        def staff(user, pw):
            g, _ = browser()
            st, body, h = g(kis + "/staff/login", {"user": user, "pw": pw})
            return g, st, h

        print("KIS Rollen")
        g0, _ = browser()
        st, body, h = g0(kis + "/staff")
        check("Ohne Anmeldung leitet das KIS zur Anmeldung um", st == 303 and "/staff/login" in h.get("Location", ""))
        g, st, h = staff("dr.beispiel", "falsch")
        check("Falsches Kennwort wird abgelehnt", "err=" in h.get("Location", ""))
        arzt, st, h = staff("dr.beispiel", "arzt-lab")
        check("Ärztin meldet sich an (Cookie HttpOnly)", st == 303 and "HttpOnly" in h.get("Set-Cookie", ""))
        pfl, _, _ = staff("schwester.test", "pflege-lab")
        emp, _, _ = staff("empfang.lab", "empfang-lab")
        abr, _, _ = staff("abrechnung.lab", "abrechnung-lab")
        adm, _, _ = staff("admin.lab", "admin-lab")

        def seite(g, path):
            st, body, h = g(kis + path)
            return st, body

        st, body = seite(arzt, "/staff/patienten")
        check("Ärztin sieht nur ihre Patienten", "Erika Beispiel" in body and "Lena Testfall" in body and "Max Mustermann" not in body)
        st, body = seite(arzt, "/staff/patient?id=P-1001")
        check("Ärztin liest Akte mit Befunden", st == 200 and "MRT Knie" in body)
        st, body = seite(arzt, "/staff/patient?id=P-1002")
        check("Ärztin ohne Behandlungsbezug wird abgewiesen", st == 403 and "Kein Behandlungsbezug" in body)
        st, body = seite(arzt, "/staff/abrechnung")
        check("Ärztin hat keinen Zugriff auf die Abrechnung", st == 403 and "keine Berechtigung" in body)
        st, body, h = arzt(kis + "/staff/notfall", {"pid": "P-1002", "grund": "x", "csrf": re.search(r'name=csrf value="([^"]+)"', arzt(kis + "/staff/patienten")[1]).group(1)})
        check("Notfallzugriff ohne Begründung wird abgelehnt", "err=" in h.get("Location", ""))
        csrf_a = re.search(r'name=csrf value="([^"]+)"', arzt(kis + "/staff/patienten")[1]).group(1)
        st, body, h = arzt(kis + "/staff/notfall", {"pid": "P-1002", "grund": "Bewusstlos eingeliefert, Vorerkrankungen klären", "csrf": csrf_a})
        check("Notfallzugriff mit Begründung öffnet die Akte", st == 303 and "patient?id=P-1002" in h.get("Location", ""))
        st, body = seite(arzt, "/staff/patient?id=P-1002")
        check("Nach Notfallzugriff ist die Akte lesbar", st == 200 and "Knöchelfraktur" in body)

        st, body = seite(pfl, "/staff/patienten")
        check("Pflege sieht nur Patienten der eigenen Station", "Max Mustermann" in body and "Erika Beispiel" not in body)
        st, body = seite(pfl, "/staff/patient?id=P-1002")
        check("Pflege sieht Medikation, aber keine Befunde", st == 200 and "Beispiel-Schmerzmittel" in body and "Röntgen Sprunggelenk" not in body and "nicht sichtbar" in body)
        csrf_p = re.search(r'name=csrf value="([^"]+)"', pfl(kis + "/staff")[1]).group(1)
        st, body, h = pfl(kis + "/staff/notfall", {"pid": "P-1001", "grund": "Ich will nur mal schauen", "csrf": csrf_p})
        check("Pflege darf keinen Notfallzugriff nutzen", st == 403)
        st, body = seite(pfl, "/staff/termine")
        check("Pflege sieht Termine, kann sie aber nicht ändern", st == 200 and "Neuer Termin" not in body and "Absagen" not in body)

        st, body = seite(emp, "/staff/patienten")
        check("Empfang sieht Stammdaten, aber keinen Aktenlink", "Erika Beispiel" in body and "staff/patient?id=" not in body)
        st, body = seite(emp, "/staff/patient?id=P-1001")
        check("Empfang darf keine Akte öffnen", st == 403)
        st, body = seite(emp, "/staff/abrechnung")
        check("Empfang darf nicht in die Abrechnung", st == 403)
        csrf_e = re.search(r'name=csrf value="([^"]+)"', emp(kis + "/staff/termine")[1]).group(1)
        st, body, h = emp(kis + "/staff/termine/neu", {"pid": "P-1002", "abteilung": "Orthopädie", "datum": next_weekday(3), "zeit": "09:30", "csrf": csrf_e})
        check("Empfang legt Termin an", "msg=" in h.get("Location", ""), h.get("Location", ""))
        st, body, h = emp(kis + "/staff/termine/neu", {"pid": "P-1002", "abteilung": "Orthopädie", "datum": next_weekday(3), "zeit": "09:30"})
        check("Anfrage ohne CSRF-Schlüssel wird abgelehnt", st == 403)

        st, body = seite(abr, "/staff/abrechnung")
        check("Abrechnung sieht Rechnungen ohne Diagnosen", st == 200 and "R-2026-0001" in body and "Bluthochdruck" not in body)
        st, body = seite(abr, "/staff/patient?id=P-1001")
        check("Abrechnung darf keine Akte öffnen", st == 403)
        st, body = seite(abr, "/staff/termine")
        check("Abrechnung darf keine Termine sehen", st == 403)
        csrf_b = re.search(r'name=csrf value="([^"]+)"', abr(kis + "/staff/abrechnung")[1]).group(1)
        st, body, h = abr(kis + "/staff/abrechnung/bezahlt", {"id": "R-2026-0001", "csrf": csrf_b})
        check("Abrechnung bucht Rechnung als bezahlt", "msg=" in h.get("Location", ""))
        st, body, h = abr(kis + "/staff/abrechnung/bezahlt", {"id": "R-2026-0001", "csrf": csrf_b})
        check("Doppelt bezahlt wird abgelehnt", "err=" in h.get("Location", ""))
        st, body, h = abr(kis + "/staff/abrechnung/neu", {"pid": "P-1003", "text": "Beratung", "betrag": "45,50", "csrf": csrf_b})
        check("Abrechnung erstellt Rechnung", "msg=" in h.get("Location", ""))
        st, body, h = abr(kis + "/staff/abrechnung/neu", {"pid": "P-1003", "text": "Zu teuer", "betrag": "-5", "csrf": csrf_b})
        check("Negative Beträge werden abgelehnt", "err=" in h.get("Location", ""))
        st, body = seite(abr, "/staff/abrechnung")
        check("Abrechnung zeigt die neue Rechnung", "Beratung" in body and "45,50" in body)

        st, body = seite(adm, "/staff/protokoll")
        check("IT-Admin sieht das Protokoll", st == 200 and "NOTFALLZUGRIFF auf P-1002" in body and "VERWEIGERT" in body and "Rechnung erstellt" in body)
        for pfad in ("/staff/patienten", "/staff/patient?id=P-1001", "/staff/termine", "/staff/abrechnung", "/staff/archiv"):
            st, body = seite(adm, pfad)
            check(f"IT-Admin sieht keine Patientendaten ({pfad.split('?')[0]})", st == 403 and "Erika" not in body)
        st, body = seite(arzt, "/staff/archiv")
        check("Archiv: Ärztin sieht nur Dokumente ihrer Patienten", "Entlassbrief" in body and "Aufnahmebogen" in body and "Herz-Ultraschall" in body)
        st, body = seite(pfl, "/staff/archiv")
        check("Archiv: Pflege hat keinen Zugriff", st == 403)
        st, body = seite(arzt, "/staff/protokoll")
        check("Protokoll nur für die IT-Administration", st == 403)
        st, body, h = arzt(kis + "/staff/logout", {"csrf": csrf_a})
        st, body = seite(arzt, "/staff/patienten")
        check("Nach Abmeldung ist die KIS-Sitzung ungültig", st == 303)
        gov = None

        print("Backup, Ransomware, Wiederherstellung")
        code, s0 = agent(PORTS["ag_kis"], "GET", "/kis/status")
        check("KIS hat beim Start ein Backup", code == 200 and len(s0["backups"]) == 1 and s0["worm"] is True)
        code, _ = agent(PORTS["ag_kis"], "POST", "/kis/backup", token="falsch")
        check("Backup ohne Token wird abgelehnt", code == 403)
        code, b1 = agent(PORTS["ag_kis"], "POST", "/kis/backup")
        check("Backup erstellen (unveränderlich)", code == 200 and b1["immutable"] and len(b1["sha256"]) == 64)
        code, v = agent(PORTS["ag_kis"], "POST", "/kis/verify", {"id": b1["id"]})
        check("Wiederherstellungstest besteht", code == 200 and v["ok"])
        agent(PORTS["ag_kis"], "POST", "/kis/worm", {"on": False})
        code, b2 = agent(PORTS["ag_kis"], "POST", "/kis/backup")
        check("Ungeschütztes Backup möglich", code == 200 and not b2["immutable"])
        st, body, h = emp(kis + "/staff/termine/neu", {"pid": "P-1001", "abteilung": "Radiologie", "datum": next_weekday(4), "zeit": "10:30", "csrf": csrf_e})
        code, s1 = agent(PORTS["ag_kis"], "GET", "/kis/status")
        check("Änderungen seit dem Backup werden gezählt", s1["changes_seit_backup"] == 1, str(s1["changes_seit_backup"]))
        code, r = agent(PORTS["ag_kis"], "POST", "/kis/ransom")
        check("Ransomware sperrt Daten, löscht nur ungeschützte Backups", code == 200 and b2["id"] in r["geloescht"] and b1["id"] in r["abgewehrt"], str(r))
        st, body, h = emp(kis + "/staff/termine")
        check("KIS meldet gesperrte Daten", st == 503 and "Daten sind verschlüsselt" in body)
        go4, _ = browser()
        st, body, h = go4(pp + "/login", {"pid": "P-1001", "pin": "1234"})
        check("Patientenportal zeigt freundliche Hinweisseite bei gesperrten Daten", st == 503 and "Gerade nicht erreichbar" in body and "Ihre Daten sind sicher" in body)
        code, _ = agent(PORTS["ag_kis"], "POST", "/kis/backup")
        check("Von gesperrten Daten darf kein Backup entstehen", code == 409)
        code, rr = agent(PORTS["ag_kis"], "POST", "/kis/restore", {})
        check("Wiederherstellung aus dem unveränderlichen Backup", code == 200 and rr["id"] == b1["id"], str(rr))
        check("Datenverlust (RPO) wird gezählt", rr.get("verlorene_aenderungen", -1) >= 1, str(rr))
        st, body, h = emp(kis + "/staff/patienten")
        check("Daten sind nach der Wiederherstellung wieder da", st == 200 and "Erika Beispiel" in body)
        go5, _ = browser()
        go5(pp + "/login", {"pid": "P-1001", "pin": "1234"})
        st, body, h = go5(pp + "/akte")
        check("Patient kann sich nach der Wiederherstellung wieder anmelden", st == 200 and "Bluthochdruck" in body)
        # Szenario ohne WORM
        agent(PORTS["ag_kis"], "POST", "/kis/worm", {"on": False})
        agent(PORTS["ag_kis"], "POST", "/kis/reset")
        agent(PORTS["ag_kis"], "POST", "/kis/backup")
        code, r = agent(PORTS["ag_kis"], "POST", "/kis/ransom")
        agent(PORTS["ag_kis"], "POST", "/kis/worm", {"on": False})
        code, rr = agent(PORTS["ag_kis"], "POST", "/kis/restore", {})
        check("Ohne unveränderliches Backup gibt es keine Wiederherstellung", code == 404, str(rr))
        agent(PORTS["ag_kis"], "POST", "/kis/reset")
        agent(PORTS["ag_kis"], "POST", "/kis/worm", {"on": True})

        print("Browser-Ersatz (/fetch)")
        code, f = agent(PORTS["ag_pp"], "POST", "/fetch", {"url": f"http://127.0.0.1:{PORTS['pp']}/", "method": "GET", "headers": {"X-Prefix": "/via/a/b"}})
        check("Fetch liefert Seite aus Sicht des Hosts", code == 200 and f["ok"] and f["status"] == 200)
        code, f = agent(PORTS["ag_pp"], "POST", "/fetch", {"url": "http://127.0.0.1:8080/", "method": "GET"})
        check("Fetch meldet Verbindungsfehler statt abzustürzen", code == 200 and f["ok"] is False and f["error"])
        code, f = agent(PORTS["ag_pp"], "POST", "/fetch", {"url": "http://8.8.8.8/", "method": "GET"})
        check("Fetch nach außerhalb des Lab-Netzes wird verweigert", code == 400)
        code, f = agent(PORTS["ag_pp"], "POST", "/fetch", {"url": f"http://127.0.0.1:{PORTS['pp']}/", "method": "GET"}, token="falsch")
        check("Fetch ohne Token wird verweigert", code == 403)
    finally:
        for p in procs:
            p.terminate()
    ok, n = sum(RES), len(RES)
    print(f"\n{ok} von {n} Prüfungen bestanden")
    return 0 if ok == n else 1


if __name__ == "__main__":
    sys.exit(main())
