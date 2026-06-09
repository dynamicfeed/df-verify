#!/usr/bin/env python3
"""
verified-agent — an example AI agent that VERIFIES the world before it acts.

The DF-VERIFY/1 pattern: an autonomous agent must not act on world-state it cannot cryptographically
verify. This fetches a signed go / caution / no-go verdict from Dynamic Feed, verifies the Ed25519
signature against the issuer's published key, and acts ONLY if the data is authentic, unaltered, and
the verdict permits it. Tamper with the data after it was signed and the agent refuses to act.

Run:
    pip install cryptography
    python agent.py                 # verify a live verdict, then act
    python agent.py --tamper        # alter the data after signing -> verification fails -> agent refuses

Self-contained: the whole verifier is the ~12 lines under "DF-VERIFY/1" below. For production, use the
packaged reference verifier instead:  pip install dynamicfeed-verify
Spec: https://dynamicfeed.ai/standard
"""
from __future__ import annotations

import argparse
import base64
import json
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BASE = "https://dynamicfeed.ai"


# ---- DF-VERIFY/1 verification (this is the entire thing) ---------------------
def _b64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify(env: dict, base: str = BASE, jwks: dict | None = None) -> dict:
    sig = (env or {}).get("signature") or {}
    if not sig.get("key_id") or not sig.get("sig"):
        return {"ok": False, "error": "no signature block"}
    payload = {k: v for k, v in env.items() if k != "signature"}
    if jwks is None:
        with urllib.request.urlopen(base.rstrip("/") + "/.well-known/keys", timeout=20) as r:
            jwks = json.load(r)
    if sig["key_id"] not in jwks:
        return {"ok": False, "error": "signing key not published (rotated or ephemeral)"}
    try:
        Ed25519PublicKey.from_public_bytes(_b64(jwks[sig["key_id"]])).verify(_b64(sig["sig"]), canonical(payload))
    except Exception as e:  # any failure => not verified
        return {"ok": False, "error": f"signature invalid: {e}"}
    return {"ok": True, "key_id": sig["key_id"], "verdict": (env.get("verdict") or {}).get("status")}
# ------------------------------------------------------------------------------


def fetch_verdict(base: str = BASE, lat: float = 51.5, lon: float = -0.12) -> dict:
    body = {"robot": {"class": "aerial"}, "location": {"lat": lat, "lon": lon}}
    req = urllib.request.Request(base.rstrip("/") + "/v1/awareness",
                                 data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.load(r)


def agent_step(env: dict, base: str = BASE, jwks: dict | None = None) -> bool:
    """Verify the world-state, THEN decide whether to act. The whole point: never act on unverified data."""
    res = verify(env, base, jwks)
    if not res["ok"]:
        print(f"⛔  REFUSING TO ACT — unverifiable world-state: {res['error']}")
        print("    An agent must never act on data it cannot prove is authentic and unaltered.")
        return False
    if res["verdict"] == "no-go":
        print(f"🛑  STAND DOWN — verified NO-GO verdict (signed by {res['key_id']}).")
        return False
    print(f"✅  VERIFIED (signed by {res['key_id']}) · verdict={res['verdict']!r} — proceeding with the action.")
    # >>> the agent's real action goes here: move, trade, file, dispatch, ... <<<
    return True


def main() -> None:
    ap = argparse.ArgumentParser(description="An AI agent that verifies before it acts (DF-VERIFY/1).")
    ap.add_argument("--tamper", action="store_true",
                    help="alter the verdict AFTER it was signed, to prove the agent refuses tampered data")
    ap.add_argument("--base", default=BASE)
    a = ap.parse_args()

    env = fetch_verdict(a.base)
    if a.tamper:
        v = env.get("verdict")
        if isinstance(v, dict):
            v["status"] = "no-go" if v.get("status") == "go" else "go"  # attacker rewrites the signed verdict
        print("⚠   tamper mode: rewrote the verdict after it was signed\n")
    raise SystemExit(0 if agent_step(env, a.base) else 1)


if __name__ == "__main__":
    main()
