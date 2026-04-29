# Test fixture corpus

This directory contains the `.kdbx` / `.key` files used by `keepass-core`'s test suite, paired with JSON sidecar files describing each fixture's expected content. Tests assert that the library's parsed output matches the sidecar.

## Regenerating the corpus

Everything in this directory (except this README) is reproducible from `generate.py`:

```bash
# One-time venv setup
python3 -m venv .venv
source .venv/bin/activate
pip install pykeepass

# Regenerate the whole corpus
python3 tests/fixtures/generate.py

# Or regenerate a single category
python3 tests/fixtures/generate.py --only keepassxc
python3 tests/fixtures/generate.py --only pykeepass
python3 tests/fixtures/generate.py --only malformed
python3 tests/fixtures/generate.py --only attachments
```

`generate.py` is the source of truth. Every fixture file here was produced by it.

## Layout

```
tests/fixtures/
├── attachments/          Source files attached by fixtures below.
│                         Deterministic content, checked in.
├── keepassxc/            KDBX3 fixtures (AES-KDF, Salsa20 inner stream)
│                         created via `keepassxc-cli`. The CLI defaults to
│                         KDBX 3.1 as of KeePassXC 2.7.7.
├── pykeepass/            KDBX4 fixtures (Argon2 KDF, ChaCha20 inner stream)
│                         created via the `pykeepass` Python library. Covers
│                         edge cases the CLI cannot produce (history, recycle
│                         bin, protected custom fields) plus a 1000-entry
│                         scaling fixture.
├── malformed/            Deliberately-broken files for negative tests
│                         (truncation, bad magic, HMAC corruption). Derived
│                         from keepassxc/kdbx3-minimal.kdbx.
├── kdbxweb/              KDBX4 fixtures created via kdbxweb (Node.js) —
│                         the same library KeeWeb.app wraps internally, so
│                         these files match the shape KeeWeb would produce.
│                         Generator metadata is hardcoded to "KdbxWeb" by
│                         the library.
├── keepassium/           Round-trip fixtures saved by KeePassium.app.
├── strongbox/            Round-trip fixtures saved by Strongbox.app.
├── macpass/              Round-trip fixtures saved by MacPass.app.
│                         All three are produced manually — see
│                         "Cross-client fixtures" below.
├── .node/                Throwaway npm project (gitignored node_modules/)
│                         for the kdbxweb generator. See gen-kdbxweb.js.
├── generate.py           Corpus generator (reproducibility entry point).
├── verify.py             Sidecar consistency checker (run before commit).
└── README.md             This file.
```

This gives both KDBX3 **and** KDBX4 coverage from day one: keepassxc-cli's
CLI defaults produce KDBX3.1 (AES-KDF), while pykeepass 4.x produces KDBX4.
Between them the corpus exercises both families of KDF, inner-stream cipher,
and outer framing that the parser needs to handle.

## Sidecar format

Every `.kdbx` has a `.json` sidecar describing the minimum properties the parser must observe:

```jsonc
{
  "description": "Human-readable explanation of what this fixture tests.",
  "format": "KDBX4",                  // or "KDBX3" when we add those
  "source": "keepassxc-cli",          // or "pykeepass" or "synthetic"
  "generated_by": "tests/fixtures/generate.py",
  "master_password": "test-basic-002",
  "key_file": null,                   // or relative path if keyfile-protected
  "database_name": "Passwords",
  "generator": "KeePassXC",
  "entry_count": 6,
  "group_count": 3,
  "group_paths": ["/Work", "/Personal"],
  "entries": [
    {
      "group": "/Work",
      "title": "Contoso Mail",
      "username": "alice@example.com",
      "url": "https://mail.contoso.example",
      "notes": "Primary work email.",
      "password_length": 12,
      "tags": ["work", "email"],
      "custom_field_count": 0,
      "attachment_count": 0,
      "attachments": []
    }
  ]
}
```

- `password_length` (not `password`) is intentional: the sidecar records structural properties, not literal secrets. The vault files contain the passwords; the sidecars describe what's expected to exist, not what the exact values are.
- Tests iterate the sidecar and assert each claim against the parsed vault.

Negative-test (malformed) fixtures use a different sidecar shape:

```jsonc
{
  "description": "Truncated at 64 bytes — past the magic, mid-header-TLV.",
  "format": "KDBX4",
  "source": "synthetic",
  "expected_error": "truncated_or_malformed_header",
  "source_fixture": "keepassxc/kdbx4-minimal.kdbx"
}
```

## Content conventions — no identifying information

All fixtures use standard crypto / documentation placeholder conventions:

| Category | Convention |
|---|---|
| Personal names | `alice`, `bob`, `charlie`, `dave`, `eve`, `mallory` |
| Email addresses | `alice@example.com` etc. (RFC 2606 reserved domains) |
| Service names | `Contoso`, `Fabrikam`, `Tailspin Toys`, `Adventure Works`, `Acme Corp` (Microsoft's fictional-company set + the universal `Acme` placeholder) |
| URLs | `https://mail.contoso.example`, etc. (`.example` is an RFC 2606 reserved TLD) |
| Entry passwords | Deterministic like `p4ss-basic-01` — never real passwords |
| Master passwords | Documented in sidecars (e.g. `test-basic-002`). These vaults contain no secrets. |
| Notes | Bland placeholders or Lorem Ipsum |
| Tags | `work`, `personal`, `email`, `banking` (generic taxonomy) |

Unicode fixtures additionally use Cyrillic, Japanese, Greek, and emoji content — chosen to exercise encoding paths, not to identify anyone.

## Attachments

All fixtures in `attachments/` are generated deterministically by `generate.py`. Their SHA-256 hashes appear in the relevant sidecars so tests can verify byte-exact attachment preservation.

| File | Size | Purpose |
|---|---|---|
| `hello.txt` | 13 B | Minimal text attachment |
| `1x1.png` | 68 B | Minimal valid PNG (single transparent pixel) |
| `10kib.bin` | 10 240 B | Mid-sized binary (deterministic seed) |
| `100kib.bin` | 102 400 B | Larger binary |
| `1mib.bin` | 1 048 576 B | Crosses the KDBX4 1 MiB HMAC block boundary |
| `empty.dat` | 0 B | Zero-byte edge case |
| `unicode-café.txt` | 37 B | Non-ASCII filename |
| `mock-key.pem` | 163 B | PEM-shaped placeholder — **not a real key** |

## Known gaps

- **Argon2-KDF KDBX3 fixtures.** KDBX 3.1 supports Argon2 as an alternative
  KDF via a header extension, but neither `keepassxc-cli` (AES-KDF default)
  nor `pykeepass` 4.x (writes KDBX4 when asked for Argon2) will produce
  such a file. Uncommon in practice; can be added later by hand-editing a
  header if needed.

- **Native KeeWeb.app fixtures** (generated via the desktop app's GUI, as opposed to the `kdbxweb` library the app bundles) are not yet present. The `kdbxweb/` corpus above covers the same on-disk format since KeeWeb is a thin wrapper around kdbxweb; the only likely difference is the `<Generator>` metadata string (`KdbxWeb` here vs possibly a different string when saved through the app). KeeWeb (the app) is built on the open-source `kdbxweb` JS library. `kdbxweb` requires an externally-supplied Argon2 implementation (it has no built-in one because Argon2 is heavy). `hash-wasm`'s Argon2 rejects hash lengths below 4 bytes, but `kdbxweb`'s self-test invokes `argon2(length=1, parallelism=32, memory=1 KiB)` to verify the implementation before it'll run. Satisfying that self-test requires either `argon2-browser` (WASM) with careful wiring, or a pure-JS Argon2 implementation. Since keepassxc-cli and pykeepass already cover KDBX4 byte-level diversity — a KeeWeb fixture would differ primarily in its `<Generator>` metadata string — this is deferred.

- **Cross-client fixtures (KeePassium, Strongbox, MacPass)** are in place — see "Cross-client fixtures" below for the round-trip recipe.

## Cross-client fixtures

Some KeePass clients ship as GUI-only macOS/iOS apps with no scriptable CLI, so their fixtures cannot be regenerated by `generate.py`. Instead they are produced by a **round-trip recipe**: open an existing seed fixture in the target client, save through the GUI, and check the result in alongside a sidecar.

This captures exactly what we want to interop-test: each client's `<Generator>` string, KDF parameter defaults, custom-data conventions, and any unknown elements they sprinkle in.

### Recipe

1. Choose a seed fixture from `keepassxc/` or `pykeepass/` — `keepassxc/kdbx3-basic.kdbx` (master password `test-basic-002`) is the canonical small seed.
2. Copy the seed into the target subdirectory, e.g.
   ```
   cp keepassxc/kdbx3-basic.kdbx keepassium/kdbx-roundtrip.kdbx
   ```
3. Open the copy in the target app, force a save (e.g. edit Notes on one entry, save, revert, save again).
4. Quit the app to flush. If the app insists on saving into its own sandbox container, use *Save As* and explicitly point it back into `tests/fixtures/<client>/`.
5. Copy the seed sidecar alongside the new file, then update: `description`, `source`, `generator`, `generated_by`, `format` (some clients silently upgrade KDBX3 → KDBX4 on save), and add a `source_seed` field pointing at the seed.
6. Run `python3 tests/fixtures/verify.py` to confirm the sidecar matches what the client wrote. Any drift (changed entry/group counts, dropped fields, added custom data) is itself a useful interop signal — record it in the sidecar's `description`.

### Existing cross-client fixtures

| File | Generator | Size | Notes |
|---|---|---|---|
| `keepassium/kdbx-roundtrip.kdbx` | `KeePassium` | 2542 B | Preserves KDBX3 format on save. All six entries / three groups round-trip with no field loss. |
| `strongbox/kdbx-roundtrip.kdbx` | `Strongbox` | 2046 B | Preserves KDBX3. Tighter on-disk encoding than the seed (2046 < 2334 B) — useful for catching parser assumptions about minimum padding. |
| `macpass/kdbx-roundtrip.kdbx` | `MacPass` | 2222 B | Preserves KDBX3. May prompt to upgrade to KDBX4 on first save in newer versions — decline to keep the round-trip apples-to-apples. |

All three were seeded from `keepassxc/kdbx3-basic.kdbx` (master password `test-basic-002`).

## Licensing note

All fixture files in this directory are original content produced by `generate.py` and carry the same dual MIT/Apache-2.0 licence as the rest of the `keepass-core` repository. No files were copied from any other KeePass implementation's test corpus.
