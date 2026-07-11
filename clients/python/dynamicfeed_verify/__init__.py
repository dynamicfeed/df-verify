"""
dynamicfeed-verify — verify Dynamic Feed (DF-VERIFY/1) Ed25519-signed responses, independently.

A signed response carries a top-level ``signature`` block. This library reproduces the DF-VERIFY/1
canonical form (JSON, keys sorted recursively, compact separators), verifies the Ed25519 signature,
and separately applies the signing-key lifecycle policy at
``<base>/.well-known/signing-key-registry.json``. A flat key map can report signature mathematics,
but cannot make the overall ``ok`` policy verdict pass.

Spec: https://dynamicfeed.ai/standard

    from dynamicfeed_verify import verify, verify_live
    env, result = verify_live()          # fetch a fresh signed verdict + verify it
    assert result["ok"]
    verify(my_signed_response)           # verify any signed response you already hold
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.request
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__version__ = "1.0.3"
DEFAULT_BASE = "https://dynamicfeed.ai"
COMPILED_MIN_REGISTRY_REVISION = 1
_UA = {"User-Agent": f"dynamicfeed-verify/{__version__} (+https://dynamicfeed.ai)"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Reject redirects so an authenticated registry origin cannot be swapped."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError(f"redirect rejected while fetching trust material ({code})")


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect)


def _urlopen_no_redirect(request, timeout):
    return _NO_REDIRECT_OPENER.open(request, timeout=timeout)


def _b64d(s: str, expected_length: Optional[int] = None) -> bytes:
    """Strictly decode canonical padded or unpadded base64url.

    ``base64.urlsafe_b64decode`` silently discards non-alphabet bytes. That is unsafe for an
    unsigned signature container because multiple signature strings can otherwise decode to the
    same Ed25519 bytes. Enforce the URL-safe alphabet, exact padding, canonical unused bits, and
    (where supplied) the protocol object's exact decoded length before returning any bytes.
    """
    if not isinstance(s, str) or re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", s) is None:
        raise ValueError("invalid base64url alphabet")
    unpadded = s.rstrip("=")
    supplied_padding = len(s) - len(unpadded)
    if len(unpadded) % 4 == 1:
        raise ValueError("invalid base64url length")
    required_padding = (-len(unpadded)) % 4
    if supplied_padding not in (0, required_padding):
        raise ValueError("invalid base64url padding")
    decoded = base64.b64decode(
        unpadded + "=" * required_padding, altchars=b"-_", validate=True,
    )
    canonical_unpadded = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if unpadded != canonical_unpadded:
        raise ValueError("non-canonical base64url encoding")
    if expected_length is not None and len(decoded) != expected_length:
        raise ValueError(f"base64url value must decode to exactly {expected_length} bytes")
    return decoded


def _unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON object key: {key}")
        out[key] = value
    return out


def _strict_loads(raw: str):
    return json.loads(raw, object_pairs_hook=_unique_object,
                      parse_constant=lambda value: (_ for _ in ()).throw(
                          ValueError(f"non-standard JSON constant: {value}")))


def _utc(value, field):
    match = (re.fullmatch(
        r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z",
        value,
    ) if isinstance(value, str) else None)
    if match is None:
        raise ValueError(f"{field} must be RFC3339 UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{field} is not a valid UTC timestamp") from exc
    expected = tuple(int(part) for part in match.groups()[:6])
    actual = (parsed.year, parsed.month, parsed.day, parsed.hour, parsed.minute, parsed.second)
    if parsed.tzinfo != timezone.utc or actual != expected:
        raise ValueError(f"{field} is not a valid UTC timestamp")
    return parsed


def _revision_context(raw: dict, *, mode: str = "live",
                      minimum_registry_revision: Optional[int] = None,
                      highest_authenticated_registry_revision: Optional[int] = None) -> dict:
    if mode not in {"live", "historical_snapshot"}:
        raise ValueError("verification mode must be live or historical_snapshot")
    revision = raw.get("registry_revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise ValueError("registry_revision must be a positive integer")
    for name, value in (("minimum_registry_revision", minimum_registry_revision),
                        ("highest_authenticated_registry_revision",
                         highest_authenticated_registry_revision)):
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 1):
            raise ValueError(f"{name} must be a positive integer")
    floor = (0 if mode == "historical_snapshot" else max(
        COMPILED_MIN_REGISTRY_REVISION,
        minimum_registry_revision or COMPILED_MIN_REGISTRY_REVISION,
        highest_authenticated_registry_revision or 0,
    ))
    if mode == "live" and revision < floor:
        raise ValueError(f"registry revision {revision} is below effective floor {floor}")
    return {"mode": mode, "registry_revision": revision, "effective_registry_floor": floor,
            "historical_snapshot": mode == "historical_snapshot"}


def validate_lifecycle_registry(raw: dict, *, mode: str = "live",
                                minimum_registry_revision: Optional[int] = None,
                                highest_authenticated_registry_revision: Optional[int] = None) -> dict:
    if not isinstance(raw, dict) or raw.get("schema") != "df-signing-key-registry/v1" \
            or raw.get("issuer") != "dynamicfeed.ai":
        raise ValueError("invalid signing-key registry identity")
    _revision_context(
        raw, mode=mode, minimum_registry_revision=minimum_registry_revision,
        highest_authenticated_registry_revision=highest_authenticated_registry_revision,
    )
    _utc(raw.get("updated_at"), "updated_at")
    keys, lifecycle, active_id = raw.get("public_keys"), raw.get("lifecycle"), raw.get("active_key_id")
    if not isinstance(keys, dict) or not keys or not isinstance(lifecycle, dict) \
            or set(keys) != set(lifecycle) or active_id not in keys:
        raise ValueError("incomplete signing-key registry")
    active = []
    for key_id, encoded in keys.items():
        public_raw = _b64d(encoded, expected_length=32)
        fingerprint = hashlib.sha256(public_raw).hexdigest()
        if len(public_raw) != 32 or key_id != "df-ed25519-" + fingerprint[:12]:
            raise ValueError(f"public key does not derive {key_id}")
        meta = lifecycle[key_id]
        if not isinstance(meta, dict) or meta.get("alg") != "Ed25519" \
                or meta.get("use") != "receipt-signing" \
                or meta.get("fingerprint_sha256") != fingerprint \
                or meta.get("public_key_retained") is not True \
                or meta.get("status") not in {"active", "retired", "compromised"}:
            raise ValueError(f"invalid lifecycle entry for {key_id}")
        first, active_from = _utc(meta.get("first_used_at"), f"{key_id}.first_used_at"), \
            _utc(meta.get("active_from"), f"{key_id}.active_from")
        if first > active_from:
            raise ValueError(f"invalid first-use interval for {key_id}")
        if meta["status"] == "active":
            active.append(key_id)
            if meta.get("retired_at") is not None or meta.get("compromised_after") is not None:
                raise ValueError(f"active key {key_id} carries retirement metadata")
        else:
            retired = _utc(meta.get("retired_at"), f"{key_id}.retired_at")
            if active_from > retired:
                raise ValueError(f"invalid retirement interval for {key_id}")
            if meta["status"] == "compromised":
                if _utc(meta.get("compromised_after"), f"{key_id}.compromised_after") > retired:
                    raise ValueError(f"invalid compromise boundary for {key_id}")
            elif meta.get("compromised_after") is not None:
                raise ValueError(f"retired key {key_id} carries compromise metadata")
    if active != [active_id] or (raw.get("authority") or {}).get("independent_registry_root") is not False:
        raise ValueError("invalid registry active key or authority classification")
    policy = raw.get("verification_policy") or {}
    for name in ("cryptographic_validity_separate_from_lifecycle",
                 "retired_keys_verify_historical_bytes",
                 "compromised_key_pre_boundary_evidence_requires_independently_validated_timestamp",
                 "receipt_issued_at_alone_is_not_independent_time_evidence"):
        if policy.get(name) is not True:
            raise ValueError("incomplete registry verification policy")
    return raw


def _policy(registry, key_id, mode="live"):
    meta = (registry.get("lifecycle") or {}).get(key_id)
    if not meta:
        return "unknown", False, False, "key absent from lifecycle registry"
    status = meta["status"]
    if mode == "historical_snapshot":
        if status == "compromised":
            return status, False, False, ("compromised key; no independently verified "
                                          "signature-inclusive pre-boundary commitment")
        policy_as_of = status in {"active", "retired"}
        return status, False, policy_as_of, (
            "historical snapshot is non-live and non-actionable; policy-as-of is reported separately"
        )
    if status == "active":
        accepted = registry.get("active_key_id") == key_id
        return status, accepted, False, "active lifecycle key"
    if status == "retired":
        return status, False, False, "retired key is not accepted for live verification"
    return status, False, False, ("compromised key; no independently verified signature-inclusive "
                                  "pre-boundary commitment")


def canonical(payload: dict) -> bytes:
    """DF-VERIFY/1 canonical bytes for ``payload`` (the response WITHOUT its ``signature`` field):
    JSON with object keys sorted recursively and compact separators, encoded UTF-8."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def fetch_keys(base: str = DEFAULT_BASE, timeout: float = 20) -> dict:
    """Fetch the JWKS-style public-key map: ``{key_id: base64url(Ed25519 public key)}``."""
    req = urllib.request.Request(base.rstrip("/") + "/.well-known/keys", headers=_UA)
    with _urlopen_no_redirect(req, timeout) as r:
        return json.load(r)


def fetch_lifecycle_registry(base: str = DEFAULT_BASE, timeout: float = 20, *,
                             minimum_registry_revision: Optional[int] = None,
                             highest_authenticated_registry_revision: Optional[int] = None) -> dict:
    """Fetch and strictly validate the current-domain lifecycle registry without cache reuse."""
    req = urllib.request.Request(
        base.rstrip("/") + "/.well-known/signing-key-registry.json",
        headers={**_UA, "Cache-Control": "no-cache"},
    )
    with _urlopen_no_redirect(req, timeout) as response:
        return validate_lifecycle_registry(
            _strict_loads(response.read().decode("utf-8")), mode="live",
            minimum_registry_revision=minimum_registry_revision,
            highest_authenticated_registry_revision=highest_authenticated_registry_revision,
        )


def verify(envelope: dict, jwks: Optional[dict] = None, base: str = DEFAULT_BASE,
           lifecycle_registry: Optional[dict] = None, *, verification_mode: str = "live",
           minimum_registry_revision: Optional[int] = None,
           highest_authenticated_registry_revision: Optional[int] = None,
           registry_source_authenticated: bool = False) -> dict:
    """Verify a DF-VERIFY/1 signed response.

    Returns a structured result including ``crypto_valid``, ``signer_accepted``, and
    ``anchor_authenticated``. The last field is ``True`` when an attached ``anchor`` was inside
    the signed bytes, ``False`` for the frozen legacy post-signature attachment convention, and
    ``None`` when no anchor is present or no signature form passed.
    Pass ``lifecycle_registry`` for out-of-band offline policy. Live mode accepts only the active
    key and enforces the compiled/caller/retained revision floor. ``historical_snapshot`` must be
    selected explicitly and never makes ``ok`` true. Callers that persist an authenticated highest
    revision should pass it back atomically; otherwise ``rollback_protected`` remains false for
    future registry updates. Caller-supplied registries and custom network origins require
    ``registry_source_authenticated=True`` before live ``ok`` can pass. Redirects fail closed.
    ``jwks`` is retained as a legacy crypto-only input: it can set
    ``crypto_valid`` but never makes ``ok`` true.
    """
    if verification_mode not in {"live", "historical_snapshot"}:
        return {"ok": False, "error": "verification_mode must be live or historical_snapshot"}
    if not isinstance(envelope, dict):
        return {"ok": False, "crypto_valid": False,
                "error": "expected a top-level JSON object"}
    sig = envelope.get("signature") or {}
    if not isinstance(sig, dict):
        return {"ok": False, "crypto_valid": False,
                "error": "signature must be a JSON object"}
    kid, sig_b64 = sig.get("key_id"), sig.get("sig")
    if not kid or not sig_b64:
        return {"ok": False, "error": "no signature block (need signature.key_id + signature.sig)"}
    if sig.get("alg") != "Ed25519" or sig.get("canonicalization") != "json-sorted-compact":
        return {"ok": False, "crypto_valid": False, "signer_accepted": False,
                "lifecycle_status": "unknown", "key_id": kid,
                "error": "unsupported signature metadata"}
    stripped = {k: v for k, v in envelope.items() if k != "signature"}
    registry = None
    registry_source = "key-bytes-only"
    source_authenticated = False
    if lifecycle_registry is not None:
        try:
            registry = validate_lifecycle_registry(
                lifecycle_registry, mode=verification_mode,
                minimum_registry_revision=minimum_registry_revision,
                highest_authenticated_registry_revision=highest_authenticated_registry_revision,
            )
            registry_source = "out-of-band"
            source_authenticated = bool(registry_source_authenticated)
        except Exception as exc:
            return {"ok": False, "crypto_valid": False, "signer_accepted": False,
                    "lifecycle_status": "unknown", "key_id": kid,
                    "error": f"invalid lifecycle registry: {exc}"}
    elif jwks is None:
        try:
            if verification_mode == "historical_snapshot":
                raise ValueError("historical_snapshot mode requires an explicitly supplied pinned registry")
            registry = fetch_lifecycle_registry(
                base, minimum_registry_revision=minimum_registry_revision,
                highest_authenticated_registry_revision=highest_authenticated_registry_revision,
            )
            is_default_origin = base.rstrip("/") == DEFAULT_BASE
            registry_source = ("current-domain-https" if is_default_origin
                               else "caller-configured-network-origin")
            source_authenticated = bool(registry_source_authenticated) or is_default_origin
        except Exception as exc:
            return {"ok": False, "crypto_valid": False, "signer_accepted": False,
                    "lifecycle_status": "unknown", "key_id": kid,
                    "error": f"could not fetch/validate lifecycle registry: {exc}"}
    keys = registry["public_keys"] if registry is not None else (jwks or {})
    if kid not in keys:
        return {"ok": False, "crypto_valid": False, "signer_accepted": False,
                "lifecycle_status": "unknown", "key_id": kid,
                "error": f"key_id {kid} not in supplied trust material"}
    try:
        public_raw = _b64d(keys[kid], expected_length=32)
        sig_bytes = _b64d(sig_b64, expected_length=64)
    except Exception as exc:
        return {"ok": False, "crypto_valid": False, "signer_accepted": False,
                "lifecycle_status": "unknown", "key_id": kid,
                "error": f"invalid signature or public-key encoding: {exc}"}
    if len(public_raw) != 32 or kid != "df-ed25519-" + hashlib.sha256(public_raw).hexdigest()[:12]:
        return {"ok": False, "crypto_valid": False, "signer_accepted": False,
                "lifecycle_status": "unknown", "key_id": kid,
                "error": "public key does not derive declared key_id"}
    if len(sig_bytes) != 64:
        return {"ok": False, "crypto_valid": False, "signer_accepted": False,
                "lifecycle_status": "unknown", "key_id": kid,
                "error": "signature must decode to 64 bytes"}
    pub = Ed25519PublicKey.from_public_bytes(public_raw)
    # Two anchor conventions coexist. Some receipts sign the body BEFORE the timestamp anchor is
    # attached — an RFC 3161 / DLT anchor is a timestamp OF the signed hash, so it can only land
    # after signing (e.g. /v1/answer, /v1/receipt). Others sign WITH the anchor already inside the
    # bytes (e.g. notary inclusion proofs). Try the strip-signature form first; if it fails and an
    # anchor is present, retry with the anchor stripped too. Accepting either form is not a
    # weakening: a forgery still needs a valid Ed25519 signature over one of the two canonical forms.
    candidates = [(stripped, True if "anchor" in stripped else None)]
    if "anchor" in stripped:
        candidates.append(({k: v for k, v in stripped.items() if k != "anchor"}, False))
    last_err = None
    anchor_authenticated = None
    for payload, anchor_scope in candidates:
        try:
            pub.verify(sig_bytes, canonical(payload))
            anchor_authenticated = anchor_scope
            break
        except Exception as e:  # noqa: BLE001 — any failure means this form did not verify
            last_err = e
    else:
        return {"ok": False, "crypto_valid": False, "signer_accepted": False,
                "lifecycle_status": "unknown" if registry is None else _policy(
                    registry, kid, verification_mode)[0],
                "key_id": kid, "error": f"signature INVALID: {last_err}"}
    status, accepted, policy_as_of, detail = _policy(registry, kid, verification_mode) \
        if registry is not None else (
            "unknown", False, False, "flat key bytes carry no lifecycle policy"
        )
    if accepted and not source_authenticated:
        accepted = False
        detail = "lifecycle registry source was not explicitly authenticated"
    revision_context = (_revision_context(
        registry, mode=verification_mode, minimum_registry_revision=minimum_registry_revision,
        highest_authenticated_registry_revision=highest_authenticated_registry_revision,
    ) if registry is not None else {
        "mode": verification_mode, "registry_revision": None,
        "effective_registry_floor": (COMPILED_MIN_REGISTRY_REVISION
                                     if verification_mode == "live" else 0),
        "historical_snapshot": verification_mode == "historical_snapshot",
    })
    rollback_protected = bool(
        verification_mode == "live" and source_authenticated
        and highest_authenticated_registry_revision is not None
        and registry is not None
        and registry["registry_revision"] >= highest_authenticated_registry_revision
    )
    # verdict is a {"status": ...} dict on awareness verdicts but a plain string (the answer) on
    # /v1/answer receipts — surface whichever is present without assuming a shape.
    v = envelope.get("verdict")
    return {
        "ok": bool(accepted), "crypto_valid": True, "signer_accepted": bool(accepted),
        "policy_as_of_accepted": bool(policy_as_of),
        "lifecycle_status": status, "trust_basis": "out-of-band" if lifecycle_registry is not None
        else ("current-domain" if registry_source == "current-domain-https"
              else ("caller-configured-network-origin" if registry is not None
                    else "key-bytes-only")),
        "registry_source": registry_source,
        "registry_source_authenticated": source_authenticated,
        "rollback_protected": rollback_protected,
        **revision_context,
        "anchor_authenticated": anchor_authenticated,
        "error": None if accepted else detail,
        "key_id": kid, "ephemeral": bool(sig.get("ephemeral_key")),
        "verdict": v.get("status") if isinstance(v, dict) else v,
        "snapshot_id": envelope.get("snapshot_id"),
    }


def verify_live(base: str = DEFAULT_BASE, robot: Optional[dict] = None,
                location: Optional[dict] = None):
    """Fetch a fresh signed awareness verdict from ``base`` and verify it. Returns ``(envelope, result)``."""
    body = {"robot": robot or {"class": "aerial"}, "location": location or {"lat": 51.5, "lon": -0.12}}
    req = urllib.request.Request(
        base.rstrip("/") + "/v1/awareness",
        data=json.dumps(body).encode(), headers={"Content-Type": "application/json", **_UA})
    with _urlopen_no_redirect(req, 25) as r:
        env = _strict_loads(r.read().decode("utf-8"))
    return env, verify(env, base=base)
