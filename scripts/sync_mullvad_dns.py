#!/usr/bin/env python3
"""scripts/sync_mullvad_dns.py — fetch Mullvad's curated DNS blocklists into the on-disk cache.

Writes `<repo>/data/intel/dns-reputation-mullvad.json` with merged categories
(malware, tracker, ad, adult, social). Cached results are used by
`orchestrator.intel.dns_reputation` for offline classification.

    python3 scripts/sync_mullvad_dns.py              # all 5 categories
    python3 scripts/sync_mullvad_dns.py --only malware,tracker,ad
    python3 scripts/sync_mullvad_dns.py --ttl 24h   # ignore cache if older

License: feeds are GPL-3.0 content licensed to Mullvad; Raphael fetches them at
runtime and does NOT redistribute them.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))
from orchestrator.intel.dns_reputation import FEEDS, _parse_list

CACHE = REPO / "data" / "intel" / "dns-reputation-mullvad.json"


def _fetch(url: str, httpx_ok: bool) -> str:
    if httpx_ok:
        import httpx  # type: ignore
        r = httpx.get(url, timeout=30.0, follow_redirects=True)
        r.raise_for_status()
        return r.text
    import urllib.request
    with urllib.request.urlopen(url, timeout=30) as resp:
        return resp.read().decode("utf-8", "replace")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=",".join(FEEDS), help="comma list of categories")
    ap.add_argument("--ttl", default="0", help="skip fetch if cache younger than HOURS (0=always)")
    ap.add_argument("--out", default=str(CACHE))
    args = ap.parse_args()

    want = [c.strip() for c in args.only.split(",") if c.strip()]
    unknown = [c for c in want if c not in FEEDS]
    if unknown:
        print(f"unknown categories: {unknown}", file=sys.stderr)
        return 2

    # ttl short-circuit
    ttl_hours = 0.0
    if args.ttl.endswith("h"):
        ttl_hours = float(args.ttl[:-1])
    out_path = Path(args.out)
    if out_path.is_file() and ttl_hours > 0:
        age = (time.time() - out_path.stat().st_mtime) / 3600
        if age < ttl_hours:
            print(f"cache fresh ({age:.1f}h < {ttl_hours}h) — nothing to do")
            return 0

    try:
        import httpx  # noqa: F401
        httpx_ok = True
    except ImportError:
        httpx_ok = False

    categories: dict = {}
    meta: dict = {"source": "https://github.com/mullvad/dns-blocklists",
                  "fetched_at": time.time(), "ttl_days": 7}
    for cat in want:
        print(f"fetching {cat}: {FEEDS[cat]}")
        try:
            text = _fetch(FEEDS[cat], httpx_ok)
        except Exception as exc:  # noqa: BLE001
            print(f"  WARN: fetch failed: {exc}", file=sys.stderr)
            continue
        rules = _parse_list(text)
        categories[cat] = sorted(rules)
        meta[cat] = {"count": len(rules)}
        print(f"  {len(rules)} rules")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"categories": categories, "meta": meta},
                                  separators=(",", ":")))
    print(f"wrote {out_path}")
    return 0 if categories else 1


if __name__ == "__main__":
    sys.exit(main())
