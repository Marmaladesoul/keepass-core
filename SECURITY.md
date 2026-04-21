# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities **privately** — do not open public GitHub issues for security bugs.

You have two options:

1. **GitHub Private Vulnerability Reporting** — use the ["Report a vulnerability"](https://github.com/Marmaladesoul/keepass-core/security/advisories/new) button on this repository's Security tab. This is the preferred channel because it provides structured triage and keeps the discussion private until disclosure.

2. **Email** — send details to **security@marmaladesoul.com**.

## What to include

- A clear description of the vulnerability and its impact
- Steps to reproduce (sample input, code snippet, or proof-of-concept)
- The affected version(s) of `keepass-core` or `keepass-merge`
- Your preferred disclosure timeline (default: 90 days)

## What to expect

- **Acknowledgement within 7 days** of receipt.
- A rough timeline for remediation within 14 days.
- Credit in the release notes (or anonymously, if you prefer).
- Coordinated disclosure — we'll work with you on the public announcement timing.

## Scope

In scope:

- Memory safety issues in parser or crypto code
- Incorrect cryptographic constructions (nonce reuse, key derivation errors, HMAC bypass, etc.)
- Malicious `.kdbx` inputs that cause panics, infinite loops, or unbounded resource consumption
- Integer overflow / underflow affecting security-critical calculations
- Bypasses of the lossless round-trip property that could enable data-loss attacks

Out of scope:

- Denial-of-service via well-formed but computationally expensive inputs (Argon2 parameters are caller-controlled by design)
- Side-channel attacks on upstream crypto crates (report those to the respective crate maintainers)
- Issues in example code or documentation that do not affect shipped library behaviour

## Threat model

`keepass-core` is a format library. It is responsible for:

- Correctly parsing and writing KDBX files (including resisting malicious inputs)
- Correctly applying KDBX-specified cryptographic primitives
- Not leaking secrets via logging, error messages, or debug output

It is **not** responsible for:

- Key storage (that's the caller's responsibility)
- Memory protection beyond `zeroize` on `Drop` for sensitive types
- Protection against a compromised process or host
