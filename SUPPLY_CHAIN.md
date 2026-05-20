# Supply-chain policy

`keepass-core` handles password vault data. A compromised transitive
dependency gets execution in the unlock pipeline alongside the master
key, so the threat model for this crate's dependencies is unusually
strict. This document records the policy we apply.

If you're reporting a vulnerability or asking about scope, see
[SECURITY.md](SECURITY.md). This document is about the *engineering
process* — what tools enforce policy in CI, which dependency bumps
need manual review, and what to do when something fires red.

## What CI enforces

Every pull request runs three supply-chain checks alongside the usual
build / test / lint matrix. All three live in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml):

- **`cargo audit`** — cross-references `Cargo.lock` against the
  [RustSec advisory database](https://rustsec.org/). Fails on any
  known CVE, yanked release, or formally unmaintained crate in the
  transitive graph.

- **`cargo deny`** — config-driven policy enforcement, see
  [`deny.toml`](deny.toml). Specifically:
  - **Licenses**: allowlist of permissive licences only (MIT,
    Apache-2.0, BSD-2/3-Clause, ISC, Zlib, Unicode, MPL-2.0). Any
    GPL/LGPL/AGPL dep would fail CI; we won't carry a copyleft
    transitive that propagates restrictions to downstream consumers.
  - **Sources**: deps must come from the official crates.io
    registry. Blocks `git = "..."` or `path = "..."` overrides
    sneaking in via a malicious PR.
  - **Bans**: `openssl` / `openssl-sys` / `native-tls` are
    explicitly denied — the RustCrypto family (pure Rust, audited,
    in-tree) covers every primitive we need, and rustls is the
    answer if we ever need TLS.
  - **Wildcards** are denied; **duplicate versions** warn.

- **`cargo fmt` / `cargo clippy --all-targets -- -D warnings`** —
  baseline hygiene. Not supply-chain per se but bundled into the
  same pre-merge gate.

A CI red is **blocking** — we don't merge PRs that fail any of these.

## Dependabot triage tiers

Dependabot is configured in
[`.github/dependabot.yml`](.github/dependabot.yml) to scan weekly and
open PRs in three flavours: per-crate, or grouped under one of the
configured umbrella groups (`rustcrypto`, `secret-hygiene`,
`parsers`).

We treat Dependabot PRs in three tiers:

### Security-critical

Crates: anything in the `rustcrypto` group (aes, cbc, ctr, chacha20,
salsa20, hmac, sha2, blake2, argon2, cipher) and the `secret-hygiene`
group (zeroize, secrecy, subtle), plus `getrandom`.

These run *inside* the cryptographic primitive boundary. A subtle
correctness regression in any of them can break confidentiality or
integrity for every vault we open.

**Process — do not auto-merge.** Per release:

1. Read each crate's published release notes.
2. Cross-check the new version against the [RustSec advisory
   database](https://rustsec.org/) for any post-release advisories.
3. Walk our consuming code for behavioural reliance (e.g. relying on
   the exact shape of a deprecated API).
4. Fix any API breakage in our code as part of the same PR.
5. Run the full test suite locally; ensure all fixtures still
   round-trip.
6. Only then merge.

### Multi-minor parser bumps

Crates: anything in the `parsers` group (quick-xml, winnow, flate2,
base64).

These parse attacker-controlled input. A parser regression that
produces wrong output or panics on malformed input becomes a
denial-of-service vector (best case) or a data-corruption vector
(worst case).

Treat as security-critical when the bump crosses two or more minor
versions, or when the release notes mention "breaking" / "behaviour
change" / "panics". Single-patch bumps with no behavioural notes can
be treated as routine.

### Routine

Everything else — patch versions of unrelated deps (`thiserror`,
`uuid`, `serde_json`, `chrono`, etc.).

CI-green Dependabot PRs in this tier can be merged after a glance at
the diff. No release-notes-reading discipline required, beyond a
sanity check that the diff is what Dependabot's title claims.

## When CI fires red

The three CI checks above pre-empt most incidents, but real ones do
happen. Response depends on what triggered:

- **`cargo audit` reports a CVE.** Upgrade the affected crate
  immediately — even if the bump is out of band relative to our
  normal Dependabot cadence. If a fixed version doesn't exist yet,
  open a tracking issue and consider whether the threat model rules
  out exploitation in our usage (e.g. the CVE requires control over
  an attacker-supplied filename and we never expose one).
  *Don't* ignore the advisory in `deny.toml` unless there is no
  remediation available; record any ignore with a dated reason and
  a follow-up issue.

- **`cargo audit` reports an unmaintained crate.** Less urgent but
  still a planning trigger. Find a maintained replacement, or
  vendor the relevant code under our own crate, or accept the risk
  with an explicit ignore + tracking issue.

- **License violation.** Fix or replace the dep. We do not widen
  the allowlist for copyleft licences; they propagate to every
  downstream consumer of `keepass-core` and undermine the dual
  MIT-or-Apache redistribution story.

- **Banned crate appears transitively.** Trace the dep graph
  (`cargo tree -i openssl-sys` etc.), identify the parent that
  pulled it in, and either swap the parent, upstream a
  feature-flag fix, or accept the risk with an explicit ignore +
  rationale.

## Future investment

Not currently in place; recorded here so the next contributor knows
where the policy ends:

- **`cargo-vet`** — per-version audit attestations, importable from
  Mozilla / Google / Embark / Zcash / ISRG trust roots. Would shift
  us from "we read the release notes" to "we (or a trusted third
  party) have read the code." Bootstrap is ~1 day; ongoing cost is
  the delta-audit per Dependabot PR. Decided against today on
  effort-vs-value grounds for a single-consumer library, but it is
  the natural next step if the audit footprint grows.

- **Reproducible builds** — out of scope for the library itself;
  belongs in the downstream binary build. Out of scope here for
  multi-quarter reasons.

## Related documents

- [SECURITY.md](SECURITY.md) — vulnerability reporting, threat
  model, in-scope / out-of-scope categories.
- [CONTRIBUTING.md](CONTRIBUTING.md) — code style, commit
  conventions, PR mechanics.
- [`deny.toml`](deny.toml) — the cargo-deny configuration this
  policy is enforced by.
- [`.github/dependabot.yml`](.github/dependabot.yml) — the
  Dependabot config defining groups + cadence.
