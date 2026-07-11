#!/usr/bin/env python3
"""Fail closed when the public verifier source regresses signing-key lifecycle policy."""

import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
OLD = "df-ed25519-4cb32e72f333"
ACTIVE = "df-ed25519-6ca0de29113b"


def require(condition, message):
    if not condition:
        raise SystemExit(f"rotation-policy: FAIL: {message}")


registry = json.loads((ROOT / "SIGNING_KEY_LIFECYCLE.json").read_text())
rust_fixture_registry = json.loads(
    (ROOT / "clients/rust/tests/fixtures/signing-key-lifecycle.json").read_text()
)
require(rust_fixture_registry == registry, "Rust packaged lifecycle fixture drifted from root")
require(registry.get("schema") == "df-signing-key-registry/v1", "wrong registry schema")
require(registry.get("registry_revision") == 1, "reviewed revision must remain explicit")
require(registry.get("active_key_id") == ACTIVE, "unexpected active key")
require(registry["lifecycle"][ACTIVE]["status"] == "active", "active key is not active")
require(registry["lifecycle"][OLD]["status"] == "compromised", "old key must remain compromised")
require(registry["lifecycle"][OLD]["compromised_after"] == "2026-07-11T00:00:00Z",
        "conservative compromise boundary changed")
require(registry["authority"]["independent_registry_root"] is False,
        "current-domain registry must not claim independent authority")

compat = json.loads((ROOT / "KNOWN_KEYS.json").read_text())
require(compat.get("deprecated") is True, "KNOWN_KEYS compatibility artifact must be deprecated")
require(compat["keys"][OLD]["status"] == "compromised", "KNOWN_KEYS hides compromise")
require(compat["keys"][OLD]["policy_accepted"] is False,
        "KNOWN_KEYS accepts the compromised key")
require(all(entry.get("policy_accepted") is False for entry in compat["keys"].values()),
        "KNOWN_KEYS compatibility archive can produce policy acceptance")
require(compat["policy"]["flat_key_acceptance_forbidden"] is True,
        "flat key acceptance was re-enabled")

python_manifest = (ROOT / "clients/python/pyproject.toml").read_text()
javascript_project = json.loads((ROOT / "clients/js/package.json").read_text())
rust_manifest = (ROOT / "clients/rust/Cargo.toml").read_text()
require(re.search(r'(?m)^name = "dynamicfeed-verify"\nversion = "1\.0\.3"$', python_manifest),
        "unexpected Python package identity or release target")
require(javascript_project["version"] == "1.0.2", "unexpected JavaScript release target")
require(re.search(r'(?m)^name = "dynamicfeed-verify"\nversion = "1\.0\.2"$', rust_manifest),
        "unexpected Rust package identity or release target")

python_source = (ROOT / "clients/python/dynamicfeed_verify/__init__.py").read_text()
javascript_source = (ROOT / "clients/js/index.js").read_text()
rust_source = (ROOT / "clients/rust/src/lib.rs").read_text()
csharp_source = (ROOT / "clients/csharp/AwarenessClient.cs").read_text()
agent_source = (ROOT / "examples/verified-agent/agent.py").read_text()
notebook_source = (ROOT / "examples/openai/grounding_on_verifiable_live_data.ipynb").read_text()
for name, source in (("Python", python_source), ("JavaScript", javascript_source),
                     ("Rust", rust_source)):
    require("registry_revision" in source or "registryRevision" in source,
            f"{name} lost revision enforcement")
    require("historical_snapshot" in source or "HistoricalSnapshot" in source,
            f"{name} lost explicit historical mode")
require("_NoRedirect" in python_source, "Python network verification follows redirects")
require("redirect: 'error'" in javascript_source, "JavaScript network verification follows redirects")
require(".redirects(0)" in rust_source, "Rust network verification follows redirects")
require("not explicitly authenticated" in python_source and "not explicitly authenticated" in javascript_source,
        "supplied/custom-origin registry can self-authenticate")
require("&& registry.registry_source_authenticated" in rust_source,
        "Rust live signer acceptance ignores registry source authentication")
require("QUARANTINED" in csharp_source and "NotSupportedException" in csharp_source,
        "C# transport sample became actionable without a verifier")
require("/.well-known/keys" not in agent_source,
        "verified-agent regressed to flat-key acceptance")
require("_NoRedirect" in agent_source, "verified-agent network verification follows redirects")
require('"action_authorized": False' in agent_source and "NO ACTION EXECUTED" in agent_source,
        "verified-agent became an actuator")
require("/.well-known/keys" not in notebook_source,
        "OpenAI example regressed to flat-key acceptance")

print("rotation-policy: PASS")
