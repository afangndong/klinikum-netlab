"""Kleine Hilfen für die HTML-Seiten von KIS und Patientenportal (ohne Zusatzpakete)."""
from __future__ import annotations

import html
import json
from urllib.parse import parse_qs

CSS = """
*{box-sizing:border-box}body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:0;background:#f3f6fa;color:#14324f}
header{background:#0b1f33;color:#fff;padding:.7rem 1.2rem;display:flex;gap:1.2rem;align-items:center;flex-wrap:wrap}
header b{font-size:1.05rem}header a{color:#cadcfc;text-decoration:none;font-size:.95rem}header a.on{color:#fff;border-bottom:2px solid #12a5a0}
main{max-width:62rem;margin:1.2rem auto;padding:0 1rem}.card{background:#fff;border:1px solid #d5dee7;border-radius:10px;padding:1rem 1.2rem;margin-bottom:1rem}
h1{font-size:1.4rem;margin:.2rem 0 1rem}h2{font-size:1.1rem;margin:.2rem 0 .6rem}table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:.45rem .5rem;border-bottom:1px solid #e6ecf2;font-size:.95rem;vertical-align:top}th{color:#5b6b7b;font-weight:600}
.mute{color:#5b6b7b;font-size:.88rem}.ok{color:#1e9e5a;font-weight:600}.warn{color:#c47f00;font-weight:600}.bad{color:#d64545;font-weight:600}
input,select,button{font:inherit;padding:.45rem .6rem;border:1px solid #b8c4d0;border-radius:6px;background:#fff}
button{background:#12a5a0;color:#fff;border-color:#12a5a0;cursor:pointer}button.sec{background:#fff;color:#14324f;border-color:#b8c4d0}
form.inline{display:inline}.flash{padding:.6rem .9rem;border-radius:8px;margin-bottom:1rem}.flash.ok{background:#e3f4ea;color:#14663b;font-weight:500}
.flash.err{background:#fbe8e8;color:#8f2525;font-weight:500}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(15rem,1fr));gap:1rem}
.big{font-size:1.8rem;font-weight:700}.banner{background:#d64545;color:#fff;padding:.8rem 1.2rem;font-weight:600}
.row{display:flex;gap:.6rem;flex-wrap:wrap;align-items:end}label{display:flex;flex-direction:column;font-size:.85rem;color:#5b6b7b;gap:.2rem}
"""


def esc(x) -> str:
    return html.escape(str(x), quote=True)


def euro(x: float) -> str:
    return f"{x:,.2f} €".replace(",", "X").replace(".", ",").replace("X", ".")


def datum(iso: str) -> str:
    try:
        y, m, d = iso.split("-")
        return f"{d}.{m}.{y}"
    except ValueError:
        return esc(iso)


def page(title: str, body: str, nav: list[tuple[str, str, str]], prefix: str, active: str, brand: str, banner: str = "") -> bytes:
    links = "".join(f'<a href="{esc(prefix + path)}" class="{"on" if key == active else ""}">{esc(label)}</a>' for key, label, path in nav)
    doc = (f'<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
           f"<title>{esc(title)} · {esc(brand)}</title><style>{CSS}</style></head><body>"
           f"{('<div class=banner>' + banner + '</div>') if banner else ''}"
           f"<header><b>{esc(brand)}</b>{links}</header><main>{body}</main></body></html>")
    return doc.encode()


def flash(msg: str | None, err: bool = False) -> str:
    return f'<div class="flash {"err" if err else "ok"}">{esc(msg)}</div>' if msg else ""


def parse_form(raw: bytes) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True).items()}


def safe_prefix(value: str | None) -> str:
    """Nur einen einfachen Pfadpräfix wie /via/gast-client/patientenportal zulassen."""
    if not value:
        return ""
    ok = all(c.isalnum() or c in "/-_" for c in value) and value.startswith("/") and "//" not in value
    return value.rstrip("/") if ok else ""


def jdump(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode()
