# Security Policy

This repository is verification tooling. The security-critical surface is the verifiers themselves: the canonicalization and the Ed25519 check. The failure that matters most is a verifier that **accepts a tampered or invalid signature as valid**, or that canonicalizes differently from the signer so a genuine signature is rejected.

## Reporting a vulnerability

Please report privately rather than opening a public issue:

- GitHub: use **Security > Report a vulnerability** (private advisory) on this repo, or
- Email: **hello@dynamicfeed.ai**

Include the affected verifier (Python / JS / C# / Rust), a minimal reproduction, and the expected versus actual verdict. A reproduction against the vectors in [`tests/vectors`](tests/vectors) is ideal.

We will acknowledge within a few days and work with you on a fix and disclosure timeline.

## Scope

In scope: any verifier producing an incorrect verdict (a false accept or a false reject), or a canonicalization that diverges from the published `json-sorted-compact` rule. Out of scope: the availability of the live `dynamicfeed.ai` endpoints (this toolkit is designed to verify offline, with no runtime dependency on the issuer).
