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
├── keepassxc/            KDBX4 fixtures created via `keepassxc-cli`
│                         (/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli)
├── pykeepass/            KDBX4 fixtures created via the `pykeepass` Python
│                         library for edge cases the CLI cannot produce
│                         (history, recycle bin, protected custom fields).
├── malformed/            Deliberately-broken files for negative tests
│                         (truncation, bad magic, HMAC corruption).
├── generate.py           Corpus generator (reproducibility entry point).
└── README.md             This file.
```

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

- **KDBX3 fixtures** are not yet present. Neither `keepassxc-cli` (KDBX4-only output) nor `pykeepass` 4.x can write KDBX3. They will be added using one of:
  - KeePass 2.x native via Mono or a Windows VM
  - `kdbxweb` (Node.js) which supports both formats
  - A hand-crafted generator using `construct`
  Until then the corpus is KDBX4-only. KDBX3 reader implementation will need fixtures added before it lands.
- **KeeWeb, Strongbox, MacPass, KeePassium fixtures** are not yet present. These will be added manually in a future pass to cover cross-client interop.

## Licensing note

All fixture files in this directory are original content produced by `generate.py` and carry the same dual MIT/Apache-2.0 licence as the rest of the `keepass-core` repository. No files were copied from any other KeePass implementation's test corpus.
