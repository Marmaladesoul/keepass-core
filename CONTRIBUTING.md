# Contributing to keepass-core

Thanks for considering a contribution. A few notes to keep the process smooth.

## Before opening a pull request

1. **Open an issue first** for anything beyond a small bug fix or typo. Larger changes should be discussed before you invest time in them — it's frustrating for everyone if a PR lands that doesn't fit the library's direction.
2. **Check the scope.** This library is deliberately scope-bounded to the KDBX format. See [README.md § Non-goals](README.md#non-goals) for what belongs elsewhere.
3. **Read the maintenance stance.** This library is maintained primarily for the needs of [Keys](https://keys.marmaladesoul.com/). PRs are welcome but no response-time SLA applies.

## Style

- Code must be `rustfmt`-clean (`cargo fmt --check`)
- Code must pass `cargo clippy --all-targets -- -D warnings`
- Public APIs need rustdoc comments; examples strongly preferred
- `#![forbid(unsafe_code)]` in `keepass-core` — no exceptions without a weighty justification
- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)

## Tests

- All PRs that touch parser or crypto code must include tests
- New parser paths should have a fixture file in `tests/fixtures/` with a JSON sidecar describing expected content
- The interop test matrix must pass — don't break round-trip compatibility with existing fixtures
- Cryptographic changes must include RFC test vectors where applicable

## Commits

- Write commit messages that explain the **why**, not just the **what**
- Sign-off is not required; we do not use a CLA
- Keep commits focused — one conceptual change per commit
- Rebase rather than merge when updating your branch

## Licence

By contributing, you agree that your contribution will be dual-licensed under MIT OR Apache-2.0, the same as the rest of the project. No additional terms apply. No CLA required.

## Reporting security issues

**Do not** open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md).
