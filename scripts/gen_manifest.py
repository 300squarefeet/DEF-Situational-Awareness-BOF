#!/usr/bin/env python3
"""scripts/gen_manifest.py — emit dist/manifest.json with SHA-256 per .o.

"""
import hashlib
import json
import sys
from pathlib import Path

DIST = Path(__file__).resolve().parents[1] / "dist"

def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def main() -> int:
    entries = []
    for p in sorted(DIST.glob("*.o")):
        entries.append({
            "name": p.stem,           # e.g. "whoami.x64"
            "file": p.name,
            "size": p.stat().st_size,
            "sha256": sha256(p),
        })
    json.dump({
        "project": "DEF-Situational-Awareness-BOF",
        "credit": "",
        "artifacts": entries,
    }, sys.stdout, indent=2)
    print()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
