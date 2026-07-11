# Security policy

## Advisory DFF-2026-07-11-01 — signer lifecycle bypass

Status: source fixes prepared; package publication and service rollout are separate release gates.

Earlier Python, JavaScript, and Rust verifiers could treat successful Ed25519 mathematics against a
flat key map as an overall accepted result. Flat key bytes contain no lifecycle status. After a key
is retired or compromised, a lifecycle-unaware verifier can therefore accept newly forged bytes as
if the signer were still authorized.

The former key `df-ed25519-4cb32e72f333` is classified compromised using the conservative boundary
`2026-07-11T00:00:00Z`. Its public key remains available for historical analysis. A caller-reported
`issued_at`, a bundle-embedded key, a self-declared registry revision, or an unverified timestamp
artifact cannot rehabilitate it.

### Affected and target versions

| Package/source | Affected | Hardened target |
|---|---:|---:|
| PyPI `dynamicfeed-verify` | `<= 1.0.2` | `1.0.3` |
| npm `@dynamicfeed/verify` | `<= 1.0.1` | `1.0.2` |
| crates.io `dynamicfeed-verify` | published `1.0.0`; prior repository source `1.0.1` | `1.0.2` |
| C# sample | all current source | quarantined pending a conformant implementation |

These target numbers describe source in this repository. They are not release attestations. Check
the package registry and the final release advisory before depending on them.

### Corrected behavior

- signature mathematics is reported separately from signer acceptance;
- exact algorithm and canonicalization metadata are enforced;
- public key bytes must derive the declared key ID;
- duplicate JSON names and malformed JSON fail closed;
- both frozen anchor signature scopes remain compatible, with explicit anchor-authentication state;
- lifecycle registries require complete key/status/fingerprint/chronology/policy relationships;
- live mode accepts only the registry's active key;
- caller-supplied registries and custom network origins require an explicit authenticated-source
  assertion before live policy can pass, and network redirects fail closed;
- retired material is historical and non-live;
- compromised keys are never policy accepted;
- `historical_snapshot` mode is explicit and never actionable;
- live registry revisions enforce the compiled, caller-supplied, and caller-retained floors;
- rollback protection is claimed only when the caller supplies authenticated retained state.

### Trust-boundary warning

`SIGNING_KEY_LIFECYCLE.json` is a reviewed out-of-band snapshot in this source repository. The same
document served by `dynamicfeed.ai` is domain-authenticated operational disclosure, not an
independent lifecycle authority. Security gates should pin trust material outside the receipt
channel and authenticate registry updates.

`KNOWN_KEYS.json` is deprecated and deliberately non-flat. It preserves both public keys and marks
the former key compromised. It must not be converted back into an additive list of accepted keys.

### C# status

The C# sample is not a reference verifier. It lacks conformance-tested canonicalization, lifecycle,
and anti-rollback logic. Its network response is explicitly unverified; compatibility methods that
could return an actionable verdict throw `NotSupportedException`.

### Package and deployment completion criteria

Do not call the rotation clean until all of the following are recorded:

1. the reviewed source commit and passing CI;
2. package builds from that exact commit;
3. registry publication through normal release controls;
4. clean-environment installation and compromised-key rejection tests for every package;
5. artifact hashes and source provenance;
6. service deployment where `/.well-known/keys` exposes only the active key and the lifecycle
   registry retains historical keys with status;
7. live endpoint, logs, and rollback verification;
8. advisory update naming the released versions and completion time.

This repository does not publish packages or deploy the service merely by merging a source PR.

## Reporting a vulnerability

Please report privately rather than opening a public issue:

- GitHub: use **Security > Report a vulnerability** on this repository; or
- email: **hello@dynamicfeed.ai**.

Include the affected implementation, version/commit, minimal reproduction, trust material used,
and expected versus actual `crypto_valid` and policy result. A fixture based on
[`tests/vectors`](tests/vectors) is ideal.

## Scope

In scope:

- false cryptographic acceptance or rejection;
- signer lifecycle or registry anti-rollback bypass;
- canonicalization divergence;
- key-ID/fingerprint confusion;
- duplicate-key parsing differences;
- anchor-scope confusion;
- a sample or CLI that turns crypto-only or unverified data into an actionable policy result.

Endpoint availability is outside this verifier repository's scope, but unsafe fallback from an
unavailable lifecycle registry is in scope.
