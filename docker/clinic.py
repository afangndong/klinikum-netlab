"""Synthetische Klinikdaten und Geschäftslogik (Seite des KIS).

Alles hier ist erfunden. Es gibt keine echten Personen und keine echten Daten.

Der Speicher liegt im Arbeitsspeicher des KIS-Containers. Er kann:
  * Patientenakte, Termine, Rechnungen und Archiv verwalten,
  * Backups erstellen (mit Prüfsumme, optional unveränderlich = WORM),
  * einen Ransomware-Angriff simulieren (Daten gesperrt, ungeschützte Backups gelöscht),
  * aus einem Backup wiederherstellen und dabei den Datenverlust (RPO) zählen.

"Unveränderlich" ist hier Programmlogik und keine Eigenschaft des Dateisystems.
In der Praxis liefern das Objektspeicher mit Object Lock oder Backup-Systeme mit Retention Lock.
"""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
import threading
import time

ABTEILUNGEN = {
    "Innere Medizin": "Dr. Beispiel",
    "Orthopädie": "Dr. Muster",
    "Kardiologie": "Dr. Test",
    "Radiologie": "Dr. Lab",
}
ZEITEN = ["08:30", "09:30", "10:30", "13:30", "14:30", "15:30"]
MAX_FEHLVERSUCHE = 5
SPERRE_S = 60


# ---------------- Rollen und Rechte (Anwendungsebene) ----------------
# Die Firewall entscheidet, wer das KIS im Netz erreicht. Die Rolle entscheidet, was man darin sehen und tun darf.
ROLLEN = {
    "arzt": {"titel": "Ärztin / Arzt", "rechte": {"patienten", "akte", "akte_befunde", "termine", "termine_aendern", "archiv"}, "bezug": True, "notfall": True},
    "pflege": {"titel": "Pflege", "rechte": {"patienten", "akte", "termine"}, "bezug": True, "notfall": False},
    "empfang": {"titel": "Empfang / Terminvergabe", "rechte": {"patienten", "termine", "termine_aendern"}, "bezug": False, "notfall": False},
    "abrechnung": {"titel": "Abrechnung", "rechte": {"patienten", "abrechnung", "abrechnung_aendern"}, "bezug": False, "notfall": False},
    "it_admin": {"titel": "IT-Administration", "rechte": {"protokoll"}, "bezug": False, "notfall": False},
}
# Benutzer mit Rolle, Kennwort (nur Lab) und Behandlungsbezug (Patienten, die sie betreuen)
_BENUTZER = {
    "dr.beispiel": {"name": "Dr. Beispiel", "rolle": "arzt", "pw": "arzt-lab", "bezug": ["P-1001", "P-1003"]},
    "schwester.test": {"name": "Schwester Test", "rolle": "pflege", "pw": "pflege-lab", "bezug": ["P-1002"]},
    "empfang.lab": {"name": "Empfang Lab", "rolle": "empfang", "pw": "empfang-lab", "bezug": []},
    "abrechnung.lab": {"name": "Abrechnung Lab", "rolle": "abrechnung", "pw": "abrechnung-lab", "bezug": []},
    "admin.lab": {"name": "IT-Admin Lab", "rolle": "it_admin", "pw": "admin-lab", "bezug": []},
}


def _hash_pw(user: str, pw: str) -> str:
    return hashlib.sha256(f"lab-salz-staff:{user}:{pw}".encode()).hexdigest()


def seed_users() -> dict:
    return {u: {"name": d["name"], "rolle": d["rolle"], "hash": _hash_pw(u, d["pw"]), "bezug": list(d["bezug"])} for u, d in _BENUTZER.items()}


def darf(rolle: str, recht: str) -> bool:
    return recht in ROLLEN.get(rolle, {}).get("rechte", set())


class Locked(Exception):
    """Die Daten sind gesperrt (Ransomware-Simulation)."""


class NotFound(Exception):
    pass


class Conflict(Exception):
    pass


class Denied(Exception):
    pass


def _hash_pin(pid: str, pin: str) -> str:
    return hashlib.sha256(f"lab-salz:{pid}:{pin}".encode()).hexdigest()


def _seed() -> dict:
    heute = dt.date.today()
    d = lambda n: (heute + dt.timedelta(days=n)).isoformat()  # noqa: E731
    p = lambda n: (heute - dt.timedelta(days=n)).isoformat()  # noqa: E731
    return {
        "patienten": {
            "P-1001": {"name": "Erika Beispiel", "geboren": "1961-04-12", "versicherung": "Lab-Kasse A", "station": "ambulant", "pin": _hash_pin("P-1001", "1234")},
            "P-1002": {"name": "Max Mustermann", "geboren": "1978-09-30", "versicherung": "Lab-Kasse B", "station": "2A", "pin": _hash_pin("P-1002", "2345")},
            "P-1003": {"name": "Lena Testfall", "geboren": "1990-01-22", "versicherung": "Lab-Kasse A", "station": "ambulant", "pin": _hash_pin("P-1003", "3456")},
        },
        "akte": {
            "P-1001": {
                "diagnosen": [{"datum": p(400), "icd": "I10", "text": "Bluthochdruck (Beispiel)"}, {"datum": p(120), "icd": "M17.1", "text": "Kniegelenksverschleiß rechts (Beispiel)"}],
                "medikation": [{"name": "Beispiel-Blutdrucksenker", "dosis": "1x täglich", "seit": p(380)}],
                "befunde": [{"datum": p(30), "typ": "MRT Knie", "ergebnis": "Leichter Gelenkverschleiß, kein Eingriff nötig (Beispieltext)"},
                            {"datum": p(14), "typ": "Blutbild", "ergebnis": "Unauffällig (Beispieltext)"}],
            },
            "P-1002": {
                "diagnosen": [{"datum": p(10), "icd": "S82.5", "text": "Knöchelfraktur links (Beispiel)"}],
                "medikation": [{"name": "Beispiel-Schmerzmittel", "dosis": "bei Bedarf", "seit": p(10)}],
                "befunde": [{"datum": p(10), "typ": "Röntgen Sprunggelenk", "ergebnis": "Fraktur, versorgt (Beispieltext)"}],
            },
            "P-1003": {
                "diagnosen": [{"datum": p(200), "icd": "I48", "text": "Vorhofflimmern (Beispiel)"}],
                "medikation": [{"name": "Beispiel-Gerinnungshemmer", "dosis": "2x täglich", "seit": p(190)}],
                "befunde": [{"datum": p(60), "typ": "Langzeit-EKG", "ergebnis": "Gelegentliche Rhythmusstörung (Beispieltext)"}],
            },
        },
        "termine": [
            {"id": "T-0001", "pid": "P-1001", "abteilung": "Orthopädie", "datum": d(3), "zeit": "09:30", "status": "geplant"},
            {"id": "T-0002", "pid": "P-1003", "abteilung": "Kardiologie", "datum": d(5), "zeit": "10:30", "status": "geplant"},
            {"id": "T-0003", "pid": "P-1001", "abteilung": "Radiologie", "datum": p(30), "zeit": "13:30", "status": "wahrgenommen"},
        ],
        "rechnungen": [
            {"id": "R-2026-0001", "pid": "P-1001", "datum": p(30), "faellig": d(-0), "status": "offen",
             "positionen": [{"text": "MRT Knie", "betrag": 312.40}, {"text": "Befundbericht", "betrag": 24.50}]},
            {"id": "R-2026-0002", "pid": "P-1001", "datum": p(120), "faellig": p(90), "status": "bezahlt",
             "positionen": [{"text": "Orthopädische Untersuchung", "betrag": 86.10}]},
            {"id": "R-2026-0003", "pid": "P-1002", "datum": p(9), "faellig": d(21), "status": "offen",
             "positionen": [{"text": "Notfallbehandlung", "betrag": 148.00}, {"text": "Röntgen Sprunggelenk", "betrag": 61.20}]},
        ],
        "archiv": [
            {"id": "A-2019-0007", "pid": "P-1001", "titel": "Entlassbrief Kniearthroskopie", "typ": "Entlassbrief", "jahr": 2019, "kb": 212,
             "text": "Entlassbrief (Beispieltext). Eingriff komplikationslos, Nachsorge in 6 Wochen."},
            {"id": "A-2021-0031", "pid": "P-1001", "titel": "Befund Herz-Ultraschall", "typ": "Befund", "jahr": 2021, "kb": 96,
             "text": "Echokardiographie (Beispieltext). Normale Pumpfunktion."},
            {"id": "A-2018-0102", "pid": "P-1003", "titel": "Aufnahmebogen", "typ": "Formular", "jahr": 2018, "kb": 58,
             "text": "Aufnahmebogen (Beispieltext)."},
        ],
        "zaehler": {"termin": 3, "rechnung": 3},
    }


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Store:
    def __init__(self, backup_dir: str | None = None):
        self.lock = threading.RLock()
        self.backup_dir = backup_dir or os.environ.get("BACKUP_DIR", "")
        self.data = _seed()
        self.locked = False
        self.changes = 0
        self.audit: list[dict] = []
        self.events: list[dict] = []
        self.backups: list[dict] = []
        self.blobs: dict[str, bytes] = {}
        self.worm = True
        self.fehlversuche: dict[str, list[float]] = {}
        self.users = seed_users()
        self.counters = {"restore_ms": 0.0, "last_lost_changes": 0}
        self.log("system", "KIS gestartet (synthetische Daten)")

    # ---------------- Protokoll ----------------
    def log(self, who: str, action: str) -> None:
        with self.lock:
            self.audit.append({"t": time.strftime("%H:%M:%S"), "who": who, "action": action})
            del self.audit[:-200]

    def event(self, text: str, level: str = "info") -> None:
        with self.lock:
            self.events.append({"t": time.strftime("%H:%M:%S"), "level": level, "text": text})
            del self.events[:-50]

    def _guard(self) -> None:
        if self.locked:
            raise Locked("Die Daten sind verschlüsselt (Simulation). Wiederherstellung aus dem Backup nötig.")

    def _changed(self) -> None:
        self.changes += 1

    # ---------------- Patientenportal ----------------
    def login(self, pid: str, pin: str) -> dict:
        with self.lock:
            self._guard()
            now = time.time()
            versuche = [t for t in self.fehlversuche.get(pid, []) if now - t < SPERRE_S]
            if len(versuche) >= MAX_FEHLVERSUCHE:
                self.log("portal", f"Login gesperrt (zu viele Fehlversuche): {pid}")
                raise Denied("Zu viele Fehlversuche. Bitte in einer Minute erneut versuchen.")
            pat = self.data["patienten"].get(pid)
            if not pat or pat["pin"] != _hash_pin(pid, pin):
                versuche.append(now)
                self.fehlversuche[pid] = versuche
                self.log("portal", f"Login fehlgeschlagen: {pid}")
                raise Denied("Patientennummer oder PIN falsch.")
            self.fehlversuche.pop(pid, None)
            self.log("portal", f"Login: {pid}")
            return {"pid": pid, "name": pat["name"]}


    def staff_login(self, user: str, pw: str) -> dict:
        with self.lock:
            now = time.time()
            versuche = [t for t in self.fehlversuche.get("u:" + user, []) if now - t < SPERRE_S]
            if len(versuche) >= MAX_FEHLVERSUCHE:
                self.log("system", f"Mitarbeiter-Login gesperrt: {user}")
                raise Denied("Zu viele Fehlversuche. Bitte in einer Minute erneut versuchen.")
            u = self.users.get(user)
            if not u or u["hash"] != _hash_pw(user, pw):
                versuche.append(now)
                self.fehlversuche["u:" + user] = versuche
                self.log("system", f"Mitarbeiter-Login fehlgeschlagen: {user}")
                raise Denied("Benutzername oder Kennwort falsch.")
            self.fehlversuche.pop("u:" + user, None)
            self.log(user, "Anmeldung")
            return {"user": user, "name": u["name"], "rolle": u["rolle"], "bezug": list(u["bezug"])}

    def notfallzugriff(self, user: str, pid: str, grund: str) -> None:
        """Break-Glass: Ärztin oder Arzt öffnet eine Akte ohne Behandlungsbezug. Erlaubt, aber mit Begründung und Protokoll."""
        with self.lock:
            self._guard()
            self._pat(pid)
            if len(grund.strip()) < 8:
                raise Conflict("Bitte eine Begründung mit mindestens 8 Zeichen angeben")
            self.log(user, f"NOTFALLZUGRIFF auf {pid}: {grund.strip()[:120]}")
            self.event(f"Notfallzugriff durch {user} auf {pid} (wird nachträglich geprüft)", "warn")

    def _pat(self, pid: str) -> dict:
        pat = self.data["patienten"].get(pid)
        if not pat:
            raise NotFound("Patient nicht gefunden")
        return pat

    def akte(self, pid: str, who: str = "portal") -> dict:
        with self.lock:
            self._guard()
            pat = self._pat(pid)
            self.log(who, f"Akte gelesen: {pid}")
            a = copy.deepcopy(self.data["akte"].get(pid, {"diagnosen": [], "medikation": [], "befunde": []}))
            return {"patient": {k: v for k, v in pat.items() if k != "pin"} | {"id": pid}, **a}

    def termine(self, pid: str | None = None) -> list[dict]:
        with self.lock:
            self._guard()
            rows = [t for t in self.data["termine"] if pid is None or t["pid"] == pid]
            return sorted(copy.deepcopy(rows), key=lambda t: (t["datum"], t["zeit"]))

    def freie_zeiten(self, abteilung: str, datum: str) -> list[str]:
        with self.lock:
            self._guard()
            belegt = {t["zeit"] for t in self.data["termine"] if t["abteilung"] == abteilung and t["datum"] == datum and t["status"] == "geplant"}
            return [z for z in ZEITEN if z not in belegt]

    def termin_neu(self, pid: str, abteilung: str, datum: str, zeit: str, who: str = "portal") -> dict:
        with self.lock:
            self._guard()
            self._pat(pid)
            if abteilung not in ABTEILUNGEN:
                raise NotFound("Unbekannte Abteilung")
            if zeit not in ZEITEN:
                raise Conflict("Ungültige Uhrzeit")
            try:
                tag = dt.date.fromisoformat(datum)
            except ValueError as exc:
                raise Conflict("Ungültiges Datum") from exc
            if tag < dt.date.today():
                raise Conflict("Der Termin liegt in der Vergangenheit")
            if tag.weekday() >= 5:
                raise Conflict("Am Wochenende gibt es keine Sprechstunde")
            if zeit not in self.freie_zeiten(abteilung, datum):
                raise Conflict("Dieser Termin ist schon vergeben")
            if any(t["pid"] == pid and t["datum"] == datum and t["zeit"] == zeit and t["status"] == "geplant" for t in self.data["termine"]):
                raise Conflict("Sie haben zu dieser Zeit schon einen Termin")
            self.data["zaehler"]["termin"] += 1
            t = {"id": f"T-{self.data['zaehler']['termin']:04d}", "pid": pid, "abteilung": abteilung, "datum": datum, "zeit": zeit, "status": "geplant"}
            self.data["termine"].append(t)
            self._changed()
            self.log(who, f"Termin angelegt: {t['id']} {pid} {abteilung} {datum} {zeit}")
            return copy.deepcopy(t)

    def termin_absagen(self, tid: str, pid: str | None = None, who: str = "portal") -> dict:
        with self.lock:
            self._guard()
            for t in self.data["termine"]:
                if t["id"] == tid:
                    if pid is not None and t["pid"] != pid:
                        self.log(who, f"VERWEIGERT: fremden Termin absagen {tid} durch {pid}")
                        raise Denied("Dieser Termin gehört nicht zu Ihrem Konto")
                    if t["status"] != "geplant":
                        raise Conflict("Nur geplante Termine lassen sich absagen")
                    t["status"] = "abgesagt"
                    self._changed()
                    self.log(who, f"Termin abgesagt: {tid}")
                    return copy.deepcopy(t)
            raise NotFound("Termin nicht gefunden")

    def rechnungen(self, pid: str | None = None) -> list[dict]:
        with self.lock:
            self._guard()
            out = []
            for r in self.data["rechnungen"]:
                if pid is None or r["pid"] == pid:
                    c = copy.deepcopy(r)
                    c["summe"] = round(sum(p["betrag"] for p in c["positionen"]), 2)
                    out.append(c)
            return sorted(out, key=lambda r: r["datum"], reverse=True)

    def rechnung_bezahlt(self, rid: str, who: str = "verwaltung") -> dict:
        with self.lock:
            self._guard()
            for r in self.data["rechnungen"]:
                if r["id"] == rid:
                    if r["status"] == "bezahlt":
                        raise Conflict("Die Rechnung ist schon bezahlt")
                    r["status"] = "bezahlt"
                    self._changed()
                    self.log(who, f"Rechnung als bezahlt verbucht: {rid}")
                    return copy.deepcopy(r)
            raise NotFound("Rechnung nicht gefunden")

    def rechnung_neu(self, pid: str, text: str, betrag: float, who: str = "verwaltung") -> dict:
        with self.lock:
            self._guard()
            self._pat(pid)
            if not text.strip() or betrag <= 0 or betrag > 100000:
                raise Conflict("Text und Betrag (größer 0) sind nötig")
            self.data["zaehler"]["rechnung"] += 1
            r = {"id": f"R-2026-{self.data['zaehler']['rechnung']:04d}", "pid": pid, "datum": dt.date.today().isoformat(),
                 "faellig": (dt.date.today() + dt.timedelta(days=30)).isoformat(), "status": "offen",
                 "positionen": [{"text": text.strip()[:80], "betrag": round(betrag, 2)}]}
            self.data["rechnungen"].append(r)
            self._changed()
            self.log(who, f"Rechnung erstellt: {r['id']} für {pid}")
            return copy.deepcopy(r)

    def archiv(self, pid: str | None = None) -> list[dict]:
        with self.lock:
            self._guard()
            return [{k: v for k, v in a.items() if k != "text"} for a in self.data["archiv"] if pid is None or a["pid"] == pid]

    def archiv_dok(self, aid: str, pid: str | None = None, who: str = "portal") -> dict:
        with self.lock:
            self._guard()
            for a in self.data["archiv"]:
                if a["id"] == aid:
                    if pid is not None and a["pid"] != pid:
                        self.log(who, f"VERWEIGERT: fremdes Dokument {aid} durch {pid}")
                        raise Denied("Dieses Dokument gehört nicht zu Ihrem Konto")
                    self.log(who, f"Archivdokument gelesen: {aid}")
                    return copy.deepcopy(a)
            raise NotFound("Dokument nicht gefunden")

    def patienten(self) -> list[dict]:
        with self.lock:
            self._guard()
            return [{"id": k, **{x: v for x, v in p.items() if x != "pin"}} for k, p in self.data["patienten"].items()]

    # ---------------- Backup ----------------
    def _snapshot_bytes(self) -> bytes:
        return json.dumps(self.data, sort_keys=True, ensure_ascii=False).encode()

    def backup(self, worm: bool | None = None, reason: str = "manuell") -> dict:
        with self.lock:
            if self.locked:
                raise Locked("Backup nicht möglich: Daten sind gesperrt. Ein verschlüsselter Stand darf nie als Backup gespeichert werden.")
            blob = self._snapshot_bytes()
            bid = f"B-{time.strftime('%Y%m%d-%H%M%S')}-{len(self.backups) + 1}"
            rec = {"id": bid, "ts": time.time(), "zeit": time.strftime("%H:%M:%S"), "sha256": _sha(blob), "bytes": len(blob),
                   "immutable": self.worm if worm is None else worm, "changes": self.changes, "verified": None, "grund": reason,
                   "records": len(self.data["termine"]) + len(self.data["rechnungen"]) + len(self.data["archiv"]) + len(self.data["patienten"])}
            self.backups.append(rec)
            self.blobs[bid] = blob
            del self.backups[:-12]
            for k in list(self.blobs):
                if k not in {b["id"] for b in self.backups}:
                    del self.blobs[k]
            if self.backup_dir:
                try:
                    os.makedirs(self.backup_dir, exist_ok=True)
                    with open(os.path.join(self.backup_dir, bid + ".json"), "wb") as f:
                        f.write(blob)
                except OSError:
                    pass
            self.event(f"Backup {bid} erstellt ({'unveränderlich' if rec['immutable'] else 'ungeschützt'}, {reason})")
            return copy.deepcopy(rec)

    def verify(self, bid: str | None = None) -> dict:
        with self.lock:
            rec = self._find(bid)
            blob = self.blobs.get(rec["id"])
            ok = blob is not None and _sha(blob) == rec["sha256"]
            rec["verified"] = ok
            rec["verified_ts"] = time.time()
            self.event(f"Wiederherstellungstest {rec['id']}: {'bestanden' if ok else 'FEHLGESCHLAGEN'}", "info" if ok else "error")
            return {"id": rec["id"], "ok": ok}

    def _find(self, bid: str | None) -> dict:
        if not self.backups:
            raise NotFound("Es gibt kein Backup")
        if bid is None:
            return self.backups[-1]
        for b in self.backups:
            if b["id"] == bid:
                return b
        raise NotFound("Backup nicht gefunden")

    def ransom(self) -> dict:
        """Simuliert den Angriff: Daten gesperrt, ungeschützte Backups gelöscht, unveränderliche bleiben."""
        with self.lock:
            geloescht, abgewehrt = [], []
            for b in list(self.backups):
                if b["immutable"]:
                    abgewehrt.append(b["id"])
                    self.log("angreifer", f"Löschversuch abgelehnt (Retention Lock): {b['id']}")
                else:
                    self.backups.remove(b)
                    self.blobs.pop(b["id"], None)
                    geloescht.append(b["id"])
                    self.log("angreifer", f"Backup gelöscht: {b['id']}")
            self.data = {"patienten": {}, "akte": {}, "termine": [], "rechnungen": [], "archiv": [], "zaehler": {"termin": 0, "rechnung": 0}}
            self.locked = True
            self.event("RANSOMWARE-SIMULATION: Daten verschlüsselt. " + (f"{len(geloescht)} ungeschützte Backups gelöscht. " if geloescht else "")
                       + (f"{len(abgewehrt)} unveränderliche Backups blieben erhalten." if abgewehrt else "Es gibt kein unveränderliches Backup."), "error")
            return {"gesperrt": True, "geloescht": geloescht, "abgewehrt": abgewehrt}

    def restore(self, bid: str | None = None) -> dict:
        with self.lock:
            t0 = time.time()
            rec = self._find(bid)
            blob = self.blobs.get(rec["id"])
            if blob is None or _sha(blob) != rec["sha256"]:
                self.event(f"Wiederherstellung aus {rec['id']} abgebrochen: Prüfsumme stimmt nicht", "error")
                raise Conflict("Prüfsumme stimmt nicht. Dieses Backup ist beschädigt.")
            lost = max(0, self.changes - rec["changes"])
            self.data = json.loads(blob.decode())
            self.locked = False
            self.changes = rec["changes"]
            ms = (time.time() - t0) * 1000
            self.counters["restore_ms"] = ms
            self.counters["last_lost_changes"] = lost
            self.log("admin", f"Wiederherstellung aus {rec['id']} ({lost} Änderungen verloren)")
            self.event(f"Wiederhergestellt aus {rec['id']}. Datenverlust: {lost} Änderungen seit diesem Backup (RPO). Dauer: {ms:.0f} ms (Simulation).")
            return {"id": rec["id"], "verlorene_aenderungen": lost, "dauer_ms": round(ms, 1)}

    def set_worm(self, on: bool) -> bool:
        with self.lock:
            self.worm = bool(on)
            self.event(f"Neue Backups werden {'unveränderlich (WORM)' if self.worm else 'ungeschützt'} gespeichert")
            return self.worm

    def reset(self) -> None:
        with self.lock:
            self.data = _seed()
            self.locked = False
            self.changes = 0
            self.backups.clear()
            self.blobs.clear()
            self.fehlversuche.clear()
            self.event("Demo zurückgesetzt")

    def status(self) -> dict:
        with self.lock:
            last = self.backups[-1] if self.backups else None
            return {
                "locked": self.locked, "worm": self.worm, "changes": self.changes,
                "changes_seit_backup": (self.changes - last["changes"]) if last else None,
                "last_backup_ts": last["ts"] if last else 0,
                "last_verified": last.get("verified") if last else None,
                "zaehler": {"patienten": len(self.data["patienten"]), "termine": len(self.data["termine"]),
                            "rechnungen": len(self.data["rechnungen"]), "archiv": len(self.data["archiv"])},
                "backups": [{k: v for k, v in b.items()} for b in self.backups],
                "events": list(self.events[-15:]), "audit": list(self.audit[-30:]),
                "restore_ms": self.counters["restore_ms"], "last_lost_changes": self.counters["last_lost_changes"],
                "now": time.time(),
            }
