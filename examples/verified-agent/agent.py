#!/usr/bin/env python3
"""Verify a live Dynamic Feed advisory without actuating from verification alone.

The example checks exact signature metadata, key-id binding, Ed25519 signature
mathematics, and current signing-key lifecycle.  The default lifecycle registry
comes from the same HTTPS domain, so it is explicitly *not* an independent trust
root.  A successful result is evidence for caller-owned policy and safety logic;
this program never invokes an actuator.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import urllib.request
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BASE = "https://dynamicfeed.ai"
MAX_JSON_BYTES = 2 * 1024 * 1024
COMPILED_MIN_REGISTRY_REVISION = 1


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Reject redirects so an authenticated registry origin cannot be swapped."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError(f"redirect rejected while fetching trust material ({code})")


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect)


def _b64(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("base64url value must be text")
    padded = value + "=" * (-len(value) % 4)
    return base64.b64decode(padded, altchars=b"-_", validate=True)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _strict_loads(raw: str):
    return json.loads(
        raw,
        object_pairs_hook=_unique_object,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-standard JSON constant: {value}")
        ),
    )


def _fetch_json(url: str, *, data: Optional[bytes] = None, timeout: float = 25):
    headers = {"Cache-Control": "no-cache", "User-Agent": "dynamicfeed-verified-agent/1"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers)
    with _NO_REDIRECT_OPENER.open(request, timeout=timeout) as response:
        raw = response.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("JSON response exceeds size limit")
    return _strict_loads(raw.decode("utf-8"))


def _utc(value, field):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{field} must be RFC3339 UTC")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != timezone.utc:
        raise ValueError(f"{field} must use UTC")
    return parsed


def _validate_registry(registry: dict, minimum_revision: int = COMPILED_MIN_REGISTRY_REVISION) -> dict:
    if not isinstance(registry, dict) or registry.get("schema") != "df-signing-key-registry/v1" \
            or registry.get("issuer") != "dynamicfeed.ai":
        raise ValueError("invalid signing-key registry identity")
    if isinstance(minimum_revision, bool) or not isinstance(minimum_revision, int) \
            or minimum_revision < COMPILED_MIN_REGISTRY_REVISION:
        raise ValueError("minimum registry revision must be a positive integer")
    revision = registry.get("registry_revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < minimum_revision:
        raise ValueError(f"registry revision is missing or below minimum {minimum_revision}")
    rollback = registry.get("rollback_protection") or {}
    if rollback.get("live_policy_minimum_revision") != revision \
            or rollback.get("live_policy_requires_authenticated_update") is not True \
            or rollback.get("historical_snapshot_mode_must_be_explicit") is not True \
            or rollback.get("self_asserted_revision_is_not_anti_rollback") is not True:
        raise ValueError("registry rollback-protection disclosure is incomplete")
    _utc(registry.get("updated_at"), "updated_at")
    keys = registry.get("public_keys")
    lifecycle = registry.get("lifecycle")
    active_id = registry.get("active_key_id")
    if not isinstance(keys, dict) or not keys or not isinstance(lifecycle, dict) \
            or set(keys) != set(lifecycle) or active_id not in keys:
        raise ValueError("incomplete signing-key registry")
    active = []
    for key_id, encoded in keys.items():
        public_raw = _b64(encoded)
        fingerprint = hashlib.sha256(public_raw).hexdigest()
        if len(public_raw) != 32 or key_id != "df-ed25519-" + fingerprint[:12]:
            raise ValueError(f"public key does not derive {key_id}")
        metadata = lifecycle[key_id]
        if not isinstance(metadata, dict) or metadata.get("alg") != "Ed25519" \
                or metadata.get("use") != "receipt-signing" \
                or metadata.get("fingerprint_sha256") != fingerprint \
                or metadata.get("public_key_retained") is not True \
                or metadata.get("status") not in {"active", "retired", "compromised"}:
            raise ValueError(f"invalid lifecycle entry for {key_id}")
        first_used = _utc(metadata.get("first_used_at"), f"{key_id}.first_used_at")
        active_from = _utc(metadata.get("active_from"), f"{key_id}.active_from")
        if first_used > active_from:
            raise ValueError(f"invalid first-use interval for {key_id}")
        if metadata["status"] == "active":
            active.append(key_id)
            if metadata.get("retired_at") is not None or metadata.get("compromised_after") is not None:
                raise ValueError(f"active key {key_id} carries retirement metadata")
        else:
            retired_at = _utc(metadata.get("retired_at"), f"{key_id}.retired_at")
            if active_from > retired_at:
                raise ValueError(f"invalid retirement interval for {key_id}")
            if metadata["status"] == "compromised":
                if _utc(metadata.get("compromised_after"), f"{key_id}.compromised_after") > retired_at:
                    raise ValueError(f"invalid compromise interval for {key_id}")
            elif metadata.get("compromised_after") is not None:
                raise ValueError(f"retired key {key_id} carries compromise metadata")
    if active != [active_id]:
        raise ValueError("active-key policy is inconsistent")
    if (registry.get("authority") or {}).get("independent_registry_root") is not False:
        raise ValueError("registry authority classification is missing")
    policy = registry.get("verification_policy") or {}
    required = (
        "cryptographic_validity_separate_from_lifecycle",
        "retired_keys_verify_historical_bytes",
        "compromised_key_pre_boundary_evidence_requires_independently_validated_timestamp",
        "receipt_issued_at_alone_is_not_independent_time_evidence",
    )
    if any(policy.get(field) is not True for field in required):
        raise ValueError("registry verification policy is incomplete")
    return registry


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify(env: dict, base: str = BASE, lifecycle_registry: Optional[dict] = None, *,
           mode: str = "live", minimum_registry_revision: int = COMPILED_MIN_REGISTRY_REVISION,
           retained_registry_revision: Optional[int] = None,
           registry_source_authenticated: bool = False) -> dict:
    """Return separate cryptographic, key-binding and lifecycle results."""
    if mode not in {"live", "historical_snapshot"}:
        return {"ok": False, "crypto_valid": False, "mode": mode,
                "error": "mode must be live or historical_snapshot"}
    if not isinstance(env, dict):
        return {"ok": False, "crypto_valid": False,
                "error": "expected a top-level JSON object"}
    floors = [COMPILED_MIN_REGISTRY_REVISION, minimum_registry_revision]
    if retained_registry_revision is not None:
        floors.append(retained_registry_revision)
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in floors):
        return {"ok": False, "crypto_valid": False, "mode": mode,
                "error": "registry revision floors must be positive integers"}
    live_revision_floor = max(floors)
    registry_validation_floor = (COMPILED_MIN_REGISTRY_REVISION
                                 if mode == "historical_snapshot" else live_revision_floor)
    signature = env.get("signature")
    if not isinstance(signature, dict):
        return {"ok": False, "crypto_valid": False, "error": "no signature object"}
    key_id = signature.get("key_id")
    signature_text = signature.get("sig")
    if signature.get("alg") != "Ed25519" \
            or signature.get("canonicalization") != "json-sorted-compact":
        return {"ok": False, "crypto_valid": False, "key_id": key_id,
                "error": "unsupported signature metadata"}
    if not isinstance(key_id, str) or not isinstance(signature_text, str):
        return {"ok": False, "crypto_valid": False, "error": "signature missing key_id or sig"}

    official_origin = base.rstrip("/") == BASE
    if lifecycle_registry is not None:
        registry_source = "out-of-band"
        source_authenticated = bool(registry_source_authenticated)
        trust_basis = ("caller-authenticated-out-of-band" if source_authenticated
                       else "caller-supplied-unauthenticated")
    else:
        registry_source = ("current-domain-https" if official_origin
                           else "caller-configured-network-origin")
        source_authenticated = official_origin
        trust_basis = ("current-domain-https" if official_origin
                       else "unauthenticated-custom-origin")
    try:
        registry = _validate_registry(lifecycle_registry, registry_validation_floor) if lifecycle_registry is not None else \
            _validate_registry(_fetch_json(
                base.rstrip("/") + "/.well-known/signing-key-registry.json", timeout=20
            ), registry_validation_floor)
    except Exception as exc:  # fail closed on registry fetch, parse, or policy errors
        return {"ok": False, "crypto_valid": False, "signer_accepted": False,
                "lifecycle_status": "unknown", "trust_basis": trust_basis,
                "registry_source": registry_source,
                "registry_source_authenticated": source_authenticated,
                "independent_trust_root": False,
                "error": f"lifecycle registry unavailable or invalid: {exc}"}
    encoded_key = registry["public_keys"].get(key_id)
    if not encoded_key:
        return {"ok": False, "crypto_valid": False, "signer_accepted": False,
                "lifecycle_status": "unknown", "key_id": key_id,
                "trust_basis": trust_basis,
                "registry_source": registry_source,
                "registry_source_authenticated": source_authenticated,
                "independent_trust_root": False,
                "error": "key absent from lifecycle registry"}
    try:
        public_raw = _b64(encoded_key)
        signature_raw = _b64(signature_text)
    except Exception as exc:
        return {"ok": False, "crypto_valid": False, "signer_accepted": False,
                "lifecycle_status": "unknown", "key_id": key_id,
                "error": f"invalid signature or public-key encoding: {exc}"}
    derived_id = "df-ed25519-" + hashlib.sha256(public_raw).hexdigest()[:12]
    key_binding_valid = len(public_raw) == 32 and derived_id == key_id
    if not key_binding_valid or len(signature_raw) != 64:
        return {"ok": False, "crypto_valid": False,
                "key_binding_valid": key_binding_valid, "signer_accepted": False,
                "lifecycle_status": "unknown", "key_id": key_id,
                "error": "signature length or key-id binding is invalid"}

    stripped = {key: value for key, value in env.items() if key != "signature"}
    candidates = [(stripped, True if "anchor" in stripped else None)]
    if "anchor" in stripped:
        candidates.append(({key: value for key, value in stripped.items() if key != "anchor"}, False))
    crypto_valid = False
    anchor_authenticated = None
    public_key = Ed25519PublicKey.from_public_bytes(public_raw)
    for payload, anchor_scope in candidates:
        try:
            public_key.verify(signature_raw, canonical(payload))
            crypto_valid = True
            anchor_authenticated = anchor_scope
            break
        except Exception:
            continue

    metadata = registry["lifecycle"][key_id]
    status = metadata["status"]
    live_signer_accepted = (source_authenticated and status == "active"
                            and registry["active_key_id"] == key_id)
    historical_accepted = crypto_valid and key_binding_valid and status in {"active", "retired"}
    signer_accepted = live_signer_accepted if mode == "live" else False
    if status == "compromised":
        lifecycle_detail = ("compromised key; no independently verified signature-inclusive "
                            "pre-boundary commitment")
    elif status == "retired":
        lifecycle_detail = "retired key accepted for historical byte verification only"
    elif not source_authenticated:
        lifecycle_detail = "lifecycle registry source was not authenticated"
    else:
        lifecycle_detail = "active lifecycle key" if signer_accepted else "active key mismatch"
    ok = mode == "live" and crypto_valid and key_binding_valid and signer_accepted
    verdict = env.get("verdict")
    return {
        "ok": ok,
        "crypto_valid": crypto_valid,
        "key_binding_valid": key_binding_valid,
        "signer_accepted": signer_accepted,
        "lifecycle_status": status,
        "mode": mode,
        "live_accepted": ok,
        "historical_accepted": historical_accepted,
        "trust_basis": trust_basis,
        "registry_source": registry_source,
        "registry_source_authenticated": source_authenticated,
        "independent_trust_root": False,
        "registry_revision": registry["registry_revision"],
        "minimum_registry_revision": (0 if mode == "historical_snapshot" else live_revision_floor),
        "revision_source": ("historical-snapshot-no-live-floor"
                            if mode == "historical_snapshot" else
                            ("durable-retained-floor" if retained_registry_revision is not None
                             else "compiled/caller-floor")),
        "rollback_protected": bool(mode == "live" and source_authenticated
                                   and retained_registry_revision is not None
                                   and registry["registry_revision"] >= retained_registry_revision),
        "action_authorized": False,
        "trust_note": ("the current-domain registry is operational disclosure, not an independent "
                       "trust root; pin it out of band for independent identity"),
        "anchor_authenticated": anchor_authenticated,
        "key_id": key_id,
        "verdict": verdict.get("status") if isinstance(verdict, dict) else verdict,
        "error": None if ok else ("signature invalid" if not crypto_valid else (
            "historical snapshot mode is non-actionable"
            if mode == "historical_snapshot" else lifecycle_detail
        )),
    }


def fetch_verdict(base: str = BASE, lat: float = 51.5, lon: float = -0.12) -> dict:
    body = {"robot": {"class": "aerial"}, "location": {"lat": lat, "lon": lon}}
    return _fetch_json(
        base.rstrip("/") + "/v1/awareness",
        data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
    )


def agent_step(env: dict, base: str = BASE) -> bool:
    """Check advisory evidence and stop before actuation."""
    result = verify(env, base)
    if not result["ok"]:
        print(f"REJECTED — advisory record not accepted: {result['error']}")
        return False
    if result["lifecycle_status"] != "active":
        print("REJECTED — a fresh real-time advisory must use the active lifecycle key")
        return False
    if result["verdict"] == "no-go":
        print(f"STAND DOWN — signed advisory says no-go (key {result['key_id']}).")
        return False
    print(
        f"ACCEPTED AS ADVISORY EVIDENCE (key {result['key_id']}, lifecycle active) · "
        f"verdict={result['verdict']!r}"
    )
    print("NO ACTION EXECUTED — caller-owned policy, independent safety checks, and authorization remain required.")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify a live advisory without actuating from it.")
    parser.add_argument("--tamper", action="store_true",
                        help="alter the verdict after signing to demonstrate rejection")
    parser.add_argument("--base", default=BASE)
    args = parser.parse_args()
    envelope = fetch_verdict(args.base)
    if args.tamper:
        verdict = envelope.get("verdict")
        if isinstance(verdict, dict):
            verdict["status"] = "no-go" if verdict.get("status") == "go" else "go"
        print("tamper mode: rewrote the verdict after signing")
    raise SystemExit(0 if agent_step(envelope, args.base) else 1)


if __name__ == "__main__":
    main()
