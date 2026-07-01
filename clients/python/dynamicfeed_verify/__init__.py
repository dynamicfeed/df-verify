"""
dynamicfeed-verify — verify Dynamic Feed (DF-VERIFY/1) Ed25519-signed responses, independently.

A signed response carries a top-level ``signature`` block. This library reproduces the DF-VERIFY/1
canonical form (JSON, keys sorted recursively, compact separators), fetches the public key published
at ``<base>/.well-known/keys``, and verifies the detached Ed25519 signature. If it verifies, the
response provably came from the issuer and has not been altered — checkable by anyone, even against us.

Spec: https://dynamicfeed.ai/standard

    from dynamicfeed_verify import verify, verify_live
    env, result = verify_live()          # fetch a fresh signed verdict + verify it
    assert result["ok"]
    verify(my_signed_response)           # verify any signed response you already hold
"""
from __future__ import annotations

import base64
import json
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__version__ = "1.0.1"
DEFAULT_BASE = "https://dynamicfeed.ai"
# Send an explicit, honest User-Agent: some WAFs (e.g. Cloudflare) 403 the default "Python-urllib".
_UA = f"dynamicfeed-verify/{__version__} (+https://dynamicfeed.ai)"


def _b64d(s: str) -> bytes:
    """Decode base64url, tolerating missing padding."""
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(payload: dict) -> bytes:
    """DF-VERIFY/1 canonical bytes for ``payload`` (the response WITHOUT its ``signature`` field):
    JSON with object keys sorted recursively and compact separators, encoded UTF-8."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def fetch_keys(base: str = DEFAULT_BASE, timeout: float = 20) -> dict:
    """Fetch the JWKS-style public-key map: ``{key_id: base64url(Ed25519 public key)}``."""
    req = urllib.request.Request(base.rstrip("/") + "/.well-known/keys", headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def verify(envelope: dict, jwks: dict | None = None, base: str = DEFAULT_BASE) -> dict:
    """Verify a DF-VERIFY/1 signed response.

    Returns ``{"ok": bool, "key_id"?, "verdict"?, "snapshot_id"?, "ephemeral"?, "error"?}``.
    Pass ``jwks`` to verify fully offline; otherwise the public key is fetched from ``base``.
    """
    sig = (envelope or {}).get("signature") or {}
    kid, sig_b64 = sig.get("key_id"), sig.get("sig")
    if not kid or not sig_b64:
        return {"ok": False, "error": "no signature block (need signature.key_id + signature.sig)"}
    payload = {k: v for k, v in envelope.items() if k != "signature"}
    keys = jwks if jwks is not None else fetch_keys(base)
    if kid not in keys:
        return {"ok": False, "key_id": kid, "error": f"key_id {kid} not in JWKS (rotated or ephemeral)"}
    try:
        Ed25519PublicKey.from_public_bytes(_b64d(keys[kid])).verify(_b64d(sig_b64), canonical(payload))
    except Exception as e:  # noqa: BLE001 — any failure means it did not verify
        return {"ok": False, "key_id": kid, "error": f"signature INVALID: {e}"}
    return {
        "ok": True, "key_id": kid, "ephemeral": bool(sig.get("ephemeral_key")),
        "verdict": (envelope.get("verdict") or {}).get("status"),
        "snapshot_id": envelope.get("snapshot_id"),
    }


def verify_live(base: str = DEFAULT_BASE, robot: dict | None = None, location: dict | None = None):
    """Fetch a fresh signed awareness verdict from ``base`` and verify it. Returns ``(envelope, result)``."""
    body = {"robot": robot or {"class": "aerial"}, "location": location or {"lat": 51.5, "lon": -0.12}}
    req = urllib.request.Request(
        base.rstrip("/") + "/v1/awareness",
        data=json.dumps(body).encode(), headers={"Content-Type": "application/json", "User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=25) as r:
        env = json.load(r)
    return env, verify(env, base=base)
