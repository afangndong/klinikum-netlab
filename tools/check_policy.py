#!/usr/bin/env python3
"""Policy-Check für CI: Topologie gültig, Sicherheitsaussagen erfüllt, nftables-Syntax ok."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from netlab import topology as T  # noqa: E402

t = T.load(ROOT / "topology" / "klinikum.yml")
problems = T.check_assertions(t)
for p in problems:
    print("FEHLER:", p)
if problems:
    sys.exit(1)
print(f"{len(t.get('assertions', []))} Sicherheitsaussagen erfüllt")
r = subprocess.run([sys.executable, str(ROOT / "tools/render.py")], capture_output=True, text=True)
print(r.stdout.strip())
if r.returncode:
    print(r.stderr)
    sys.exit(r.returncode)
nft = subprocess.run(["nft", "-c", "-f", str(ROOT / "build/fw/nftables.conf")], capture_output=True, text=True)
if nft.returncode:
    print("nft-Syntaxfehler:", nft.stderr)
    sys.exit(1)
print("nftables-Syntax ok")
