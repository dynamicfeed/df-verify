#!/usr/bin/env python3
"""Live-Data Integrity Report — a reproducible measurement anyone can re-run.

For a set of live-data domains an AI agent might call, this fetches the datapoint from Dynamic Feed,
checks its Ed25519 signature and signer lifecycle with the reviewed out-of-band registry in this
repository, and records three separate facts:

  freshness   — how old the newest datapoint is (from its own timestamp)
  provenance  — does the datapoint name its source + observation time?
  accepted    — do signature mathematics and signer lifecycle policy both pass? (yes/no)

The report checks only what each returned object actually contains. It does not assume an upstream
source lacks provenance, and signer-policy acceptance does not establish objective truth.

    python -m pip install -e ../../clients/python
    python report.py           # prints the table + a headline, writes results.json

Re-run it any day, against live sources, and reproduce the number yourself.
"""
import json, pathlib, urllib.request
from datetime import datetime, timezone

from dynamicfeed_verify import _strict_loads, _urlopen_no_redirect, verify

BASE = "https://dynamicfeed.ai"
REGISTRY_PATH = pathlib.Path(__file__).resolve().parents[2] / "SIGNING_KEY_LIFECYCLE.json"
REGISTRY = json.loads(REGISTRY_PATH.read_text())

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
    request = urllib.request.Request(url, headers={"User-Agent": "df-integrity-report"})
    with _urlopen_no_redirect(request, 25) as response:
        return _strict_loads(response.read().decode("utf-8"))

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
    rows, accepted_count = [], 0
    for label, path, source in DOMAINS:
        try:
            resp = fetch(path)
            res = verify(
                resp,
                lifecycle_registry=REGISTRY,
                highest_authenticated_registry_revision=REGISTRY["registry_revision"],
                registry_source_authenticated=True,
            )
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
                         "policy_accepted": ok, "crypto_valid": res.get("crypto_valid"),
                         "signer_status": res.get("lifecycle_status"),
                         "provenance": prov, "reliability": conf,
                         "freshness_min": age, "measured_at": measured})
            accepted_count += 1 if ok else 0
        except Exception as e:
            rows.append({"domain": label, "public_source": source, "policy_accepted": False,
                         "error": f"{type(e).__name__}: {e}"})
    n = len(DOMAINS)
    out = {"report": "live-data-integrity/v1", "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "policy_accepted_count": accepted_count, "total": n, "rows": rows,
           "registry_revision": REGISTRY["registry_revision"],
           "headline": f"{accepted_count}/{n} live responses passed signature mathematics and the pinned signer-lifecycle "
                       f"policy. This records integrity and attribution under that policy, not objective truth or "
                       f"safety."}
    def _fresh(m):
        if m is None: return "-"
        return f"{m:.0f}m" if m < 90 else f"{m/60:.1f}h"
    print(f"\nLive-Data Integrity Report  ·  {out['generated_at']}\n")
    print(f"{'domain':22} {'accepted':10} {'reliability':11} {'freshness':10} source")
    print("-" * 78)
    for r in rows:
        print(f"{r['domain']:22} {('YES' if r.get('policy_accepted') else 'no'):10} "
              f"{(r.get('reliability') or '-'):11} {_fresh(r.get('freshness_min')):10} "
              f"{(r.get('provenance') or r.get('public_source') or '')}")
    print("\n" + out["headline"] + "\n")
    json.dump(out, open("results.json", "w"), indent=2)
    print("wrote results.json")

if __name__ == "__main__":
    main()
