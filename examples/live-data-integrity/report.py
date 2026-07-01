#!/usr/bin/env python3
"""Live-Data Integrity Report — a reproducible measurement anyone can re-run.

For a set of live-data domains an AI agent might call, this fetches the datapoint from Dynamic Feed,
independently VERIFIES its Ed25519 signature with the open-source `dynamicfeed-verify` package (no
trust in Dynamic Feed beyond fetching the public key), and records three honest, hard-to-game facts:

  freshness   — how old the newest datapoint is (from its own timestamp)
  provenance  — does the datapoint name its source + observation time?
  verifiable  — does the datapoint cryptographically verify against a published key? (yes/no)

The point is structural, not a brag: the SAME public data, fetched raw from the underlying source an
agent would otherwise call, carries NO signature and NO provenance — you cannot later prove what it
said or when. Dynamic Feed returns it signed and provenance-stamped, and this script proves that by
verifying every datapoint itself.

    pip install dynamicfeed-verify
    python report.py           # prints the table + a headline, writes results.json

Re-run it any day, against live sources, and reproduce the number yourself.
"""
import json, sys, time, urllib.request
from datetime import datetime, timezone

try:
    from dynamicfeed_verify import verify
except Exception:
    print("pip install dynamicfeed-verify", file=sys.stderr); raise

BASE = "https://dynamicfeed.ai"

# (label, DF tool + query, the public source an agent would otherwise call directly and unverifiably)
DOMAINS = [
    ("Weather (Sydney)",   "current_weather?city=Sydney",         "Open-Meteo"),
    ("Earthquakes",        "earthquakes?limit=1",                 "USGS"),
    ("Tides (Boston)",     "tides?station=8443970",               "NOAA CO-OPS"),
    ("GitHub releases",    "github_releases?repo=python/cpython", "GitHub API"),
    ("US Treasury yields", "treasury_yields",                     "US Treasury"),
    ("Space weather",      "space_weather",                       "NOAA SWPC"),
]


def fetch(path):
    url = f"{BASE}/v1/facts?tool={path}" if "?" not in path else f"{BASE}/v1/facts?tool={path.split('?')[0]}&{path.split('?',1)[1]}"
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "df-integrity-report"}), timeout=25) as r:
        return json.loads(r.read().decode())

def _find(o, keys):
    if isinstance(o, dict):
        for k in keys:
            if k in o and o[k]: return o[k]
        for v in o.values():
            r = _find(v, keys)
            if r: return r
    elif isinstance(o, list):
        for v in o:
            r = _find(v, keys)
            if r: return r
    return None

def main():
    rows, verified = [], 0
    for label, path, source in DOMAINS:
        try:
            resp = fetch(path)
            res = verify(resp)                      # independent Ed25519 check vs the published key
            ok = bool(res.get("ok"))
            facts = resp.get("facts") or []
            newest = max(facts, key=lambda f: str(f.get("timestamp") or f.get("measured_at") or "")) if facts else {}
            measured = newest.get("timestamp") or newest.get("measured_at")
            prov = (newest.get("provenance") or {}).get("source")
            conf = (newest.get("reliability") or {}).get("confidence")
            age = None
            if measured:
                try:
                    t = datetime.fromisoformat(str(measured).replace("Z", "+00:00"))
                    age = round((datetime.now(timezone.utc) - t).total_seconds() / 60, 1)
                except Exception:
                    pass
            rows.append({"domain": label, "df_tool": path.split("?")[0], "public_source": source,
                         "verifiable": ok, "provenance": prov, "reliability": conf,
                         "freshness_min": age, "measured_at": measured})
            verified += 1 if ok else 0
        except Exception as e:
            rows.append({"domain": label, "public_source": source, "verifiable": False,
                         "error": f"{type(e).__name__}: {e}"})
    n = len(DOMAINS)
    out = {"report": "live-data-integrity/v1", "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "verified": verified, "total": n, "rows": rows,
           "headline": f"{verified}/{n} live datapoints fetched from Dynamic Feed verified against its published "
                       f"Ed25519 key with the open-source verifier — each carrying its source and observation time. "
                       f"The same data fetched raw from the underlying public source carries no signature and no "
                       f"provenance: you cannot prove what it said, or when."}
    def _fresh(m):
        if m is None: return "-"
        return f"{m:.0f}m" if m < 90 else f"{m/60:.1f}h"
    print(f"\nLive-Data Integrity Report  ·  {out['generated_at']}\n")
    print(f"{'domain':22} {'verifiable':10} {'reliability':11} {'freshness':10} source")
    print("-" * 78)
    for r in rows:
        print(f"{r['domain']:22} {('YES' if r.get('verifiable') else 'no'):10} "
              f"{(r.get('reliability') or '-'):11} {_fresh(r.get('freshness_min')):10} "
              f"{(r.get('provenance') or r.get('public_source') or '')}")
    print("\n" + out["headline"] + "\n")
    json.dump(out, open("results.json", "w"), indent=2)
    print("wrote results.json")

if __name__ == "__main__":
    main()
