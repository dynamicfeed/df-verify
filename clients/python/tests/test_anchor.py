"""Offline regression tests for the anchor-convention fix (dynamicfeed-verify).

A /v1/answer receipt carries a top-level ``anchor`` block attached AFTER signing (an RFC 3161 / DLT
anchor is a timestamp OF the signed hash, so it can only land post-signing). A verifier that strips
only ``signature`` recomputes the wrong bytes and wrongly reports INVALID. These fixtures were
captured live from dynamicfeed.ai (2026-07-09); the key df-ed25519-… is persistent. No network.

Run:  python -m pytest clients/python/tests   (or)   python clients/python/tests/test_anchor.py
"""
import copy
import json
import pathlib
from unittest import mock

import dynamicfeed_verify as verifier
from dynamicfeed_verify import _b64d, _strict_loads, validate_lifecycle_registry, verify

FIX = pathlib.Path(__file__).parent / "fixtures"
REGISTRY = json.loads((pathlib.Path(__file__).parents[3] / "SIGNING_KEY_LIFECYCLE.json").read_text())


def _jwks(kid_pubkey_file: str, kid: str) -> dict:
    return {kid: (FIX / kid_pubkey_file).read_text().strip()}


def _load(name: str) -> dict:
    return json.loads((FIX / name).read_text())


def test_anchored_answer_crypto_valid_but_compromised_lifecycle_rejected():
    env = _load("answer_anchored.json")
    assert "anchor" in env, "fixture must carry an anchor block"
    res = verify(env, lifecycle_registry=REGISTRY)
    assert res["crypto_valid"] is True and res["ok"] is False, res
    assert res["lifecycle_status"] == "compromised"
    assert res["anchor_authenticated"] is False


def test_noanchor_awareness_crypto_valid_but_compromised_lifecycle_rejected():
    env = _load("awareness_noanchor.json")
    assert "anchor" not in env, "fixture must have no anchor block"
    res = verify(env, lifecycle_registry=REGISTRY)
    assert res["crypto_valid"] is True and res["ok"] is False, res
    assert res["lifecycle_status"] == "compromised"
    assert res["anchor_authenticated"] is None


def test_flat_key_map_is_crypto_only():
    env = _load("awareness_noanchor.json")
    kid = env["signature"]["key_id"]
    res = verify(env, jwks=_jwks("awareness_pubkey.txt", kid))
    assert res["crypto_valid"] is True and res["ok"] is False
    assert res["lifecycle_status"] == "unknown"


def test_body_tamper_is_invalid():
    env = _load("answer_anchored.json")
    kid = env["signature"]["key_id"]
    bad = copy.deepcopy(env)
    for k, v in bad.items():
        if k not in ("signature", "anchor") and isinstance(v, str) and v:
            bad[k] = v + "X"
            break
    res = verify(bad, lifecycle_registry=REGISTRY)
    assert not res["crypto_valid"] and not res["ok"], "a tampered body must verify INVALID"


def test_live_registry_revision_floor_is_fail_closed_and_not_self_supplied():
    for value in (None, False, 0, 1.5):
        bad = copy.deepcopy(REGISTRY)
        if value is None:
            bad.pop("registry_revision", None)
        else:
            bad["registry_revision"] = value
        try:
            validate_lifecycle_registry(bad)
        except ValueError as exc:
            assert "registry_revision" in str(exc)
        else:
            raise AssertionError(f"invalid revision accepted: {value!r}")

    assert validate_lifecycle_registry(REGISTRY, minimum_registry_revision=1) is REGISTRY
    try:
        validate_lifecycle_registry(REGISTRY, minimum_registry_revision=2)
    except ValueError as exc:
        assert "below effective floor" in str(exc)
    else:
        raise AssertionError("caller-retained floor was ignored")


def test_historical_snapshot_is_explicit_non_actionable_and_revision_visible():
    env = _load("awareness_noanchor.json")
    result = verify(
        env, lifecycle_registry=REGISTRY, verification_mode="historical_snapshot",
        minimum_registry_revision=2, registry_source_authenticated=True,
    )
    assert result["ok"] is False
    assert result["historical_snapshot"] is True
    assert result["mode"] == "historical_snapshot"
    assert result["registry_revision"] == 1
    assert result["effective_registry_floor"] == 0
    assert result["rollback_protected"] is False
    assert result["lifecycle_status"] == "compromised"


def test_live_result_discloses_revision_and_no_durable_floor_claim():
    env = _load("awareness_noanchor.json")
    result = verify(env, lifecycle_registry=REGISTRY, registry_source_authenticated=True)
    assert result["registry_revision"] == 1
    assert result["effective_registry_floor"] == 1
    assert result["mode"] == "live"
    assert result["rollback_protected"] is False


def test_strict_json_base64_and_timestamp_inputs_fail_closed():
    assert verify([])["ok"] is False
    assert verify({"signature": "attacker"})["ok"] is False
    for raw in ('{"schema":"a","schema":"b"}', '{"value":NaN}'):
        try:
            _strict_loads(raw)
        except ValueError:
            pass
        else:
            raise AssertionError(f"non-strict JSON accepted: {raw}")
    for encoded in ("!!!!", "A", "AA=", "AA===", "+A==", "AB", "abc$", "===="):
        try:
            _b64d(encoded)
        except ValueError:
            pass
        else:
            raise AssertionError(f"malformed base64url accepted: {encoded}")
    bad = copy.deepcopy(REGISTRY)
    bad["updated_at"] = "2026-02-30T10:00:00Z"
    try:
        validate_lifecycle_registry(bad)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid calendar timestamp accepted")
    malformed = _load("awareness_noanchor.json")
    malformed["signature"]["sig"] = "!!!!"
    result = verify(
        malformed, lifecycle_registry=REGISTRY, registry_source_authenticated=True,
    )
    assert result["ok"] is False and result["crypto_valid"] is False
    assert "encoding" in result["error"]


def test_signature_text_malleability_and_wrong_decoded_lengths_fail_closed():
    env = _load("awareness_noanchor.json")
    signature_text = env["signature"]["sig"]
    assert len(_b64d(signature_text, expected_length=64)) == 64

    # Python's permissive urlsafe_b64decode accepts both of these mutations as the same 64 bytes.
    # The signature block is outside the signed payload, so accepting either spelling would create
    # a cross-verifier signature-text malleability gap.
    for mutated_text in ("!" + signature_text, signature_text + "!"):
        mutated = copy.deepcopy(env)
        mutated["signature"]["sig"] = mutated_text
        result = verify(
            mutated, lifecycle_registry=REGISTRY, registry_source_authenticated=True,
        )
        assert result["ok"] is False and result["crypto_valid"] is False
        assert "encoding" in result["error"]

    for encoded, expected_length in (("AA", 64), ("AA", 32)):
        try:
            _b64d(encoded, expected_length=expected_length)
        except ValueError as exc:
            assert "exactly" in str(exc)
        else:
            raise AssertionError("wrong decoded length accepted")


def test_custom_network_origin_does_not_self_authenticate():
    env = _load("awareness_noanchor.json")
    key_id = env["signature"]["key_id"]
    active_registry = copy.deepcopy(REGISTRY)
    active_registry["active_key_id"] = key_id
    active_registry["public_keys"] = {key_id: REGISTRY["public_keys"][key_id]}
    metadata = active_registry["lifecycle"][key_id]
    metadata.update({"status": "active", "retired_at": None, "compromised_after": None})
    active_registry["lifecycle"] = {key_id: metadata}
    supplied = verifier.verify(env, lifecycle_registry=active_registry)
    assert supplied["crypto_valid"] is True and supplied["ok"] is False
    assert supplied["error"] == "lifecycle registry source was not explicitly authenticated"
    supplied_authenticated = verifier.verify(
        env, lifecycle_registry=active_registry, registry_source_authenticated=True,
    )
    assert supplied_authenticated["ok"] is True

    with mock.patch.object(verifier, "fetch_lifecycle_registry", return_value=active_registry):
        custom = verifier.verify(
            env, base="https://mirror.example",
            highest_authenticated_registry_revision=1,
        )
        assert custom["trust_basis"] == "caller-configured-network-origin"
        assert custom["registry_source_authenticated"] is False
        assert custom["rollback_protected"] is False
        assert custom["ok"] is False
        explicit = verifier.verify(
            env, base="https://mirror.example",
            highest_authenticated_registry_revision=1,
            registry_source_authenticated=True,
        )
        assert explicit["registry_source_authenticated"] is True
        assert explicit["rollback_protected"] is True
        assert explicit["ok"] is True


if __name__ == "__main__":
    test_anchored_answer_crypto_valid_but_compromised_lifecycle_rejected()
    test_noanchor_awareness_crypto_valid_but_compromised_lifecycle_rejected()
    test_flat_key_map_is_crypto_only()
    test_body_tamper_is_invalid()
    print("PASS — historical crypto valid, compromised lifecycle rejected, body tamper caught")
