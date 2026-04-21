# keepass-core

A pure Rust implementation of the [KeePass](https://keepass.info/) (KDBX) password database format.

Full lossless round-trip read/write for KDBX3 and KDBX4, preserving unknown XML elements for forward compatibility. Interop-tested against KeePass2, KeePassXC, KeeWeb, Strongbox, KeePassium, and MacPass.

Sister crate [`keepass-merge`](crates/keepass-merge) implements three-way merge for reconciling external changes.

## Status

**Pre-release — not yet published to crates.io.** The library is under active development. Follow the repository for the first v0.1 release.

## Features

- **KDBX3 and KDBX4** read/write (full round-trip)
- **Lossless** — unknown XML elements are preserved and re-emitted untouched
- **Pure Rust** — no C dependencies
- **Memory-safe** — `#![forbid(unsafe_code)]` in the core crate
- **Battle-tested crypto** — built on the `RustCrypto` family (`argon2`, `aes`, `aes-gcm`, `chacha20`, `sha2`, `hmac`, `blake2`)
- **Continuous fuzzing** via `cargo-fuzz`
- **Interop matrix** — tested against files produced by every major KeePass client

## Example

```rust
// Pending — API sketch:
// let vault = keepass_core::Vault::open(path, password)?;
// for entry in vault.entries() {
//     println!("{}", entry.title());
// }
```

## Non-goals

This crate intentionally does **not** implement:

- KeePass 1.x `.kdb` (a different format entirely)
- Password generation, strength estimation, or TOTP (these belong in application code, not the format library)
- High-level convenience wrappers unrelated to the KDBX format
- Async I/O (the crate is sync; wrap with `spawn_blocking` if you need non-blocking)
- A command-line tool (may live in a separate `keepass-cli` crate later)

## Maintenance

This library is maintained primarily for the needs of [Keys](https://keys.marmaladesoul.com/), a commercial password manager. Pull requests are welcome; issues are triaged on a best-effort basis; there is no SLA on response times. For production use, pin a specific version.

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure process.

## Licence

Dual-licensed under either of:

- [MIT licence](LICENSE-MIT) ([SPDX: MIT](https://spdx.org/licenses/MIT.html))
- [Apache Licence, Version 2.0](LICENSE-APACHE) ([SPDX: Apache-2.0](https://spdx.org/licenses/Apache-2.0.html))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work shall be dual-licensed as above, without any additional terms or conditions.

## Related crates on crates.io

- [`keepass`](https://crates.io/crates/keepass) (sseemayer) — the current incumbent. Mature, active, but KDBX4 write support is explicitly experimental and drops unrecognised XML fields.
- [`keepass-ng`](https://crates.io/crates/keepass-ng) — fork of the above with enhancements.
- [`rust-kpdb`](https://crates.io/crates/rust-kpdb) — dual MIT/Apache-2.0, KeePass 2 focused.
- [`kdbx-rs`](https://crates.io/crates/kdbx-rs) — GitLab-hosted alternative, MIT.
- [`kdbx4`](https://crates.io/crates/kdbx4) — KDBX4 reader only, inactive.

`keepass-core` differentiates itself by targeting production-grade lossless round-trip from the first stable release.
