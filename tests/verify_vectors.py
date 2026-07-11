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
import json
import pathlib
import sys

VEC = pathlib.Path(__file__).parent / "vectors"
ROOT = VEC.parents[1]
sys.path.insert(0, str(ROOT / "clients" / "python"))

from dynamicfeed_verify import canonical as client_canonical  # noqa: E402
from dynamicfeed_verify import verify as client_verify  # noqa: E402

REGISTRY = json.loads((ROOT / "SIGNING_KEY_LIFECYCLE.json").read_text())


def canonical(payload):
    p = {k: v for k, v in payload.items() if k != "signature"} if isinstance(payload, dict) else payload
    return client_canonical(p)


def verify(env, keys):
    result = client_verify(env, jwks=keys)
    assert result["ok"] is False, "flat key bytes must never imply lifecycle acceptance"
    return result.get("crypto_valid") is True


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

    lifecycle = client_verify(json.loads(sv["authentic"]["envelope_text"]),
                              lifecycle_registry=REGISTRY)
    lifecycle_ok = (lifecycle.get("crypto_valid") is True
                    and lifecycle.get("ok") is False
                    and lifecycle.get("lifecycle_status") == "compromised")
    fails += not lifecycle_ok
    print(f"  [{'PASS' if lifecycle_ok else 'FAIL'}] lifecycle · compromised historical signer rejected")

    av = json.loads((VEC / "signed-answer-anchored.json").read_text())
    akeys = av["public_keys"]
    aa = verify(json.loads(av["authentic"]["envelope_text"]), akeys)
    am = verify(json.loads(av["anchor_modified"]["envelope_text"]), akeys)
    at = verify(json.loads(av["tampered"]["envelope_text"]), akeys)
    fails += (not aa) + (not am) + (at is True)
    print(f"  [{'PASS' if aa else 'FAIL'}] anchored answer · authentic verifies (anchor stripped)")
    print(f"  [{'PASS' if am else 'FAIL'}] anchored answer · anchor-modified STILL verifies (anchor is unsigned)")
    print(f"  [{'PASS' if not at else 'FAIL'}] anchored answer · tampered signed field rejected")

    n = len(cv["vectors"]) + 6
    print(f"\n{'✓ ALL ' + str(n) + ' VECTORS PASS' if not fails else '✗ ' + str(fails) + ' FAILED'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
