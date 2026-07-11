import base64
import hashlib
import importlib.util
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


SPEC = importlib.util.spec_from_file_location("verified_agent", Path(__file__).with_name("agent.py"))
agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent)


def identity(private_key):
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    fingerprint = hashlib.sha256(raw).hexdigest()
    return raw, fingerprint, "df-ed25519-" + fingerprint[:12]


def metadata(fingerprint, status):
    active = status == "active"
    return {
        "alg": "Ed25519", "use": "receipt-signing", "fingerprint_sha256": fingerprint,
        "status": status, "first_used_at": "2026-07-01T00:00:00Z",
        "active_from": "2026-07-01T00:00:00Z",
        "retired_at": None if active else "2026-07-03T00:00:00Z",
        "compromised_after": None if active else "2026-07-02T00:00:00Z",
        "public_key_retained": True,
    }


class VerifiedAgentTests(unittest.TestCase):
    def setUp(self):
        self.old_private = Ed25519PrivateKey.generate()
        self.active_private = Ed25519PrivateKey.generate()
        old_raw, old_fingerprint, self.old_id = identity(self.old_private)
        active_raw, active_fingerprint, self.active_id = identity(self.active_private)
        self.registry = {
            "schema": "df-signing-key-registry/v1", "issuer": "dynamicfeed.ai",
            "registry_revision": 1,
            "updated_at": "2026-07-11T00:00:00Z", "active_key_id": self.active_id,
            "public_keys": {
                self.old_id: base64.urlsafe_b64encode(old_raw).decode(),
                self.active_id: base64.urlsafe_b64encode(active_raw).decode(),
            },
            "lifecycle": {
                self.old_id: metadata(old_fingerprint, "compromised"),
                self.active_id: metadata(active_fingerprint, "active"),
            },
            "authority": {"independent_registry_root": False},
            "verification_policy": {
                "cryptographic_validity_separate_from_lifecycle": True,
                "retired_keys_verify_historical_bytes": True,
                "compromised_key_pre_boundary_evidence_requires_independently_validated_timestamp": True,
                "receipt_issued_at_alone_is_not_independent_time_evidence": True,
            },
            "rollback_protection": {
                "live_policy_minimum_revision": 1,
                "live_policy_requires_authenticated_update": True,
                "historical_snapshot_mode_must_be_explicit": True,
                "self_asserted_revision_is_not_anti_rollback": True,
            },
        }

    def envelope(self, private_key, key_id, *, anchor=None):
        body = {"schema": "awareness/v1", "verdict": {"status": "caution"}}
        signature = private_key.sign(agent.canonical(body))
        envelope = dict(body)
        if anchor is not None:
            envelope["anchor"] = anchor
        envelope["signature"] = {
            "alg": "Ed25519", "key_id": key_id,
            "canonicalization": "json-sorted-compact",
            "sig": base64.urlsafe_b64encode(signature).decode().rstrip("="),
        }
        return envelope

    def test_active_passes_and_compromised_rejects(self):
        active = agent.verify(
            self.envelope(self.active_private, self.active_id),
            lifecycle_registry=self.registry,
            registry_source_authenticated=True,
        )
        self.assertTrue(active["ok"])
        compromised = agent.verify(
            self.envelope(self.old_private, self.old_id),
            lifecycle_registry=self.registry,
            registry_source_authenticated=True,
        )
        self.assertTrue(compromised["crypto_valid"])
        self.assertFalse(compromised["ok"])
        self.assertEqual(compromised["lifecycle_status"], "compromised")

    def test_legacy_anchor_scope_is_reported(self):
        result = agent.verify(
            self.envelope(
                self.active_private, self.active_id,
                anchor={"status": "imprint_matched_unverified"},
            ),
            lifecycle_registry=self.registry,
            registry_source_authenticated=True,
        )
        self.assertTrue(result["ok"])
        self.assertFalse(result["anchor_authenticated"])

    def test_strict_json_and_metadata(self):
        self.assertFalse(agent.verify([])["ok"])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            agent._strict_loads('{"a":1,"a":2}')
        envelope = self.envelope(self.active_private, self.active_id)
        envelope["signature"]["alg"] = "ed25519"
        self.assertFalse(agent.verify(
            envelope, lifecycle_registry=self.registry, registry_source_authenticated=True,
        )["ok"])

    def test_registry_revision_is_positive_and_meets_floor(self):
        for revision in (None, 0, True):
            bad = json.loads(json.dumps(self.registry))
            if revision is None:
                bad.pop("registry_revision")
            else:
                bad["registry_revision"] = revision
            self.assertFalse(agent.verify(
                self.envelope(self.active_private, self.active_id),
                lifecycle_registry=bad,
                registry_source_authenticated=True,
            )["ok"])
        self.assertFalse(agent.verify(
            self.envelope(self.active_private, self.active_id),
            lifecycle_registry=self.registry,
            minimum_registry_revision=2,
            registry_source_authenticated=True,
        )["ok"])

    def test_custom_origin_does_not_self_authenticate(self):
        envelope = self.envelope(self.active_private, self.active_id)
        with mock.patch.object(agent, "_fetch_json", return_value=self.registry):
            custom = agent.verify(envelope, base="https://attacker.invalid")
        self.assertTrue(custom["crypto_valid"])
        self.assertFalse(custom["ok"])
        self.assertEqual(custom["registry_source"], "caller-configured-network-origin")
        self.assertFalse(custom["registry_source_authenticated"])

    def test_success_does_not_actuate(self):
        accepted = {
            "ok": True, "lifecycle_status": "active", "verdict": "caution",
            "key_id": self.active_id,
        }
        output = io.StringIO()
        with mock.patch.object(agent, "verify", return_value=accepted), redirect_stdout(output):
            self.assertTrue(agent.agent_step({}))
        self.assertIn("NO ACTION EXECUTED", output.getvalue())

    def test_registry_source_and_historical_mode_are_explicit(self):
        envelope = self.envelope(self.active_private, self.active_id)
        unauthenticated = agent.verify(
            envelope,
            lifecycle_registry=self.registry,
            retained_registry_revision=1,
        )
        self.assertFalse(unauthenticated["ok"])
        self.assertFalse(unauthenticated["registry_source_authenticated"])
        self.assertFalse(unauthenticated["independent_trust_root"])
        self.assertFalse(unauthenticated["rollback_protected"])

        authenticated = agent.verify(
            envelope,
            lifecycle_registry=self.registry,
            retained_registry_revision=1,
            registry_source_authenticated=True,
        )
        self.assertTrue(authenticated["rollback_protected"])
        historical = agent.verify(
            envelope,
            lifecycle_registry=self.registry,
            mode="historical_snapshot",
            minimum_registry_revision=2,
            retained_registry_revision=2,
            registry_source_authenticated=True,
        )
        self.assertTrue(historical["crypto_valid"])
        self.assertTrue(historical["historical_accepted"])
        self.assertFalse(historical["ok"])
        self.assertFalse(historical["action_authorized"])
        self.assertEqual(historical["minimum_registry_revision"], 0)
        self.assertEqual(historical["revision_source"], "historical-snapshot-no-live-floor")


if __name__ == "__main__":
    unittest.main()
