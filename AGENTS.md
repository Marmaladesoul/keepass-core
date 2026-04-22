# AGENTS.md — working on keepass-core

Guidance for AI coding agents (Claude Code, Cursor, Aider, Codex, …)
contributing to this crate. Humans are also welcome to read it.

## What this project is

A pure-Rust, lossless round-trip read/write implementation of the
KeePass (KDBX) password-database format. Public library, MIT /
Apache dual-licensed. Consumed downstream via a private FFI facade
into the macOS Keys app.

The canonical design doc is `_design/` (git-ignored, author-only).
Key cross-referenced sections are quoted inline in commits when
relevant — e.g. §4.8.7 on error-collapse discipline.

## How to work

### Ship style

- **Small, bounded PRs.** One concept per PR. Each one CI-green on
  its own. The existing commit history (`git log --oneline main`)
  is the style guide.
- **Every decoder change ships with an encoder test that
  round-trips the same shape, and vice versa.** Asymmetry between
  read and write is how round-trip fidelity bugs get in.
- **Never skip a test because it's slow.** The downstream Keys app
  is macOS-first, so macOS CI coverage in particular is not
  optional.
- **Don't stack branches.** One PR open, merge, next PR from main.
- **Don't start parallel slices.** Finish and merge before
  branching the next.

### Rigor

- **Correctness over cleverness.** Illegal states unrepresentable
  via the type system rather than checked at runtime.
- **`#![forbid(unsafe_code)]` at the crate root.** No exceptions.
- **Constant-time compare every hash / HMAC / keystream byte.**
  The `subtle` crate is the default.
- **Error-collapse discipline (§4.8.7).** "Wrong key" and "corrupt
  ciphertext" surface as the *same* error variant. Distinguishing
  them leaks an oracle to an attacker.
- **`#[non_exhaustive]` on every public enum and every public
  struct whose field set might grow.** Adding a field is then a
  minor version, not a breaking change.
- **Newtypes for every semantic quantity** (`EntryId`, `GroupId`,
  `CompositeKey`, `TransformedKey`, `CipherKey`, `HmacBaseKey`,
  `MasterSeed`, …). Never a naked `Uuid` or `[u8; 32]` across a
  public boundary.
- **Per-module `thiserror` enums, wrapped transparently at the
  top level.**

### Idioms

- **`quick-xml` for XML.** `winnow` for binary TLV parsing.
  `RustCrypto` family for every primitive. No hand-rolled crypto.
- **Sealed traits** where external implementers would be a foot-gun
  (e.g. `Cipher`). Lets us evolve the trait without a semver break.
- **Typestate** (`Kdbx<Sealed>` → `<HeaderRead>` → `<Unlocked>`)
  makes "you can't unlock a sealed file" a compile error.
- **`zeroize` / `secrecy` on every key-bearing type.** Manually
  redacted `Debug`. Never `Display`.

### Testing

- **Unit tests next to the code**, inside `#[cfg(test)] mod tests`.
- **Integration tests against real fixtures** in
  `tests/fixtures/` — a corpus of KDBX files emitted by
  KeePassXC / pykeepass / kdbxweb, each with a JSON sidecar.
  Every pipeline PR must round-trip at least the fixtures it
  plausibly touches.
- **Byte-level assertions where they're cheap.** SHA-256 of
  decoded attachment bytes against sidecar hashes is the gold
  standard.
- **`proptest` or `insta` are welcome** when a feature genuinely
  benefits, but don't add either until there's a test that wants
  them.

### Don'ts

- Don't re-invent a primitive that already lives in `crypto::` or
  `format::` — wire what's there.
- Don't commit anything from `_design/` or any vault / keyfile /
  password outside `tests/fixtures/`.
- Don't "fallback to a deprecated method" without asking first
  (standing project rule).
- Don't skip hooks or sign-off (`--no-verify`, `--no-gpg-sign`) —
  investigate a hook failure, don't bypass it.

## PR template

Title: `subsystem: what the PR does (imperative)`.

Body: a Summary section (1–3 bullets or short prose) plus a Test
plan checklist. The `git log` is full of examples — match that
shape.

Commits: write a short body that explains the *why*, not the
*what*. Diff tells you what; the body tells you why it's
correct.

## Collaboration rhythm

- Agents: work autonomously via `/loop` where appropriate, schedule
  your own CI wake-ups, one PR then stop. When you hit a real
  design decision that needs human input, stop and ask.
- Humans: review the PR on GitHub; merging is gated by "all CI
  green + one human 👀".
