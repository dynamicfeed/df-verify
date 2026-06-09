#!/usr/bin/env python3
"""
DF-VERIFY/1 conformance harness — checks an implementation against the published test vectors.

  python3 tests/verify_vectors.py

Validates two things every conformant verifier must get right:
  1. Canonicalization — for each vector, canonical(payload) must equal the expected bytes
     (key sorting, compact separators, ensure_ascii \\uXXXX escaping incl. astral surrogate pairs,
     and stripping the top-level `signature` field).
  2. Signature verification — the `authentic` signed envelope must verify against its published key;
     the `tampered` twin must be rejected.

Exit code 0 = all vectors pass. The vectors themselves (tests/vectors/*.json) are language-agnostic;
port this harness to confirm a JS/Go/Rust/etc. verifier byte-for-byte.
"""
import base64
import json
import pathlib
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

VEC = pathlib.Path(__file__).parent / "vectors"


def canonical(payload):
    p = {k: v for k, v in payload.items() if k != "signature"} if isinstance(payload, dict) else payload
    return json.dumps(p, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify(env, keys):
    sig = env.get("signature") or {}
    payload = {k: v for k, v in env.items() if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(_b64(keys[sig["key_id"]])).verify(_b64(sig["sig"]), canonical(payload))
        return True
    except Exception:
        return False


def main():
    fails = 0

    cv = json.loads((VEC / "canonicalization.json").read_text())
    for v in cv["vectors"]:
        got = canonical(v["payload"]).decode("utf-8")
        ok = got == v["canonical"]
        fails += not ok
        print(f"  [{'PASS' if ok else 'FAIL'}] canon · {v['name']}")
        if not ok:
            print(f"         expected {v['canonical']!r}\n         got      {got!r}")

    sv = json.loads((VEC / "signed-awareness.json").read_text())
    keys = sv["public_keys"]
    a = verify(json.loads(sv["authentic"]["envelope_text"]), keys)
    t = verify(json.loads(sv["tampered"]["envelope_text"]), keys)
    fails += (not a) + (t is True)
    print(f"  [{'PASS' if a else 'FAIL'}] signature · authentic envelope verifies")
    print(f"  [{'PASS' if not t else 'FAIL'}] signature · tampered envelope rejected")

    n = len(cv["vectors"]) + 2
    print(f"\n{'✓ ALL ' + str(n) + ' VECTORS PASS' if not fails else '✗ ' + str(fails) + ' FAILED'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
