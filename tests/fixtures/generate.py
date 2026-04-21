#!/usr/bin/env python3
"""
Regenerate the entire test-fixture corpus from scratch.

This script is the source of truth for every `.kdbx` and `.key` file under
`tests/fixtures/`. It is deterministic and idempotent — running it twice
produces the same byte-for-byte output (modulo KDBX's random IVs, which
are seeded here for reproducibility).

Usage:
    source .venv/bin/activate      # or set up a venv first — see below
    python3 tests/fixtures/generate.py [--only <category>]

Categories:
    keepassxc   — fixtures created via `keepassxc-cli` (system-installed)
    pykeepass   — fixtures created via the `pykeepass` library (pure Python)
    malformed   — deliberately-broken files for negative tests
    attachments — regenerate the source attachments (rarely needed)

Requirements:
    - KeePassXC installed (for keepassxc-cli): https://keepassxc.org/
    - A Python venv with `pykeepass` installed:
        python3 -m venv .venv
        source .venv/bin/activate
        pip install pykeepass

Output: each fixture lives in its category subdirectory alongside a JSON
sidecar describing the expected content. Rust tests in
`crates/keepass-core/tests/` read both and assert that the library's
parsed output matches the sidecar.

Content conventions (NO identifying information):
    - Usernames: alice, bob, charlie, dave, eve, mallory
    - Emails: alice@example.com (RFC 2606 reserved domains)
    - Service names: Contoso, Fabrikam, Tailspin Toys, Acme Corp
    - URLs: https://example.com, https://example.org, https://example.net
    - Master passwords are deliberately weak and documented — these vaults
      contain NO secrets, only test data.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# -----------------------------------------------------------------------------
# Paths
# -----------------------------------------------------------------------------

HERE = Path(__file__).resolve().parent           # tests/fixtures/
ATTACHMENTS = HERE / "attachments"
KEEPASSXC_DIR = HERE / "keepassxc"
PYKEEPASS_DIR = HERE / "pykeepass"
MALFORMED_DIR = HERE / "malformed"

KEEPASSXC_CLI = "/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli"

# -----------------------------------------------------------------------------
# Fixed test data — no identifying information
# -----------------------------------------------------------------------------

PEOPLE = ["alice", "bob", "charlie", "dave", "eve", "mallory"]

SERVICES = [
    # (title, url) — fake companies from Microsoft's official fictional set
    # plus classic "Acme" (universally recognised as synthetic).
    ("Contoso Mail", "https://mail.contoso.example"),
    ("Fabrikam VPN", "https://vpn.fabrikam.example"),
    ("Tailspin Toys Store", "https://toys.tailspin.example"),
    ("Adventure Works", "https://adventure-works.example"),
    ("Acme Banking", "https://bank.acme.example"),
    ("Acme Cloud", "https://cloud.acme.example"),
]

LOREM = (
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Test fixture "
    "note field for round-trip verification. Contains no sensitive data."
)


@dataclass
class EntrySpec:
    """What we want an entry to look like, and what the sidecar will assert."""
    path: str                                    # KeePassXC group-path/title
    title: str
    username: str
    url: str
    password: str
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    custom_fields: dict[str, tuple[str, bool]] = field(default_factory=dict)
    # field_name -> (value, is_protected)
    attachments: dict[str, Path] = field(default_factory=dict)
    # attachment_name_in_vault -> source file under ATTACHMENTS/
    totp_seed: str | None = None                 # otpauth-style secret


# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------

def log(msg: str) -> None:
    print(f"[fixtures] {msg}", file=sys.stderr)


def sha256_of(path: Path) -> str:
    """Hex SHA-256 of a file."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_sidecar(path: Path, data: dict) -> None:
    """Write a sidecar JSON file with stable key ordering + trailing newline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")


def run_cli(*args: str, stdin: str = "", check: bool = True) -> subprocess.CompletedProcess:
    """Run keepassxc-cli with sensible defaults, feeding stdin for password prompts."""
    result = subprocess.run(
        [KEEPASSXC_CLI, *args],
        input=stdin,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"keepassxc-cli {' '.join(args)} failed\n"
            f"  stdout: {result.stdout}\n"
            f"  stderr: {result.stderr}"
        )
    return result


def ensure_keepassxc_available() -> None:
    if not Path(KEEPASSXC_CLI).is_file():
        raise SystemExit(
            f"KeePassXC not installed at {KEEPASSXC_CLI}.\n"
            "Install via: brew install --cask keepassxc"
        )


# -----------------------------------------------------------------------------
# Attachment regeneration (deterministic)
# -----------------------------------------------------------------------------

def generate_attachments() -> None:
    """Regenerate all source attachments deterministically.

    Normally the attachments are checked in and never need regenerating,
    but this function documents how each was produced.
    """
    import random
    import zlib
    import struct

    ATTACHMENTS.mkdir(parents=True, exist_ok=True)

    (ATTACHMENTS / "hello.txt").write_bytes(b"Hello, world\n")

    # 1x1 transparent PNG
    sig = b"\x89PNG\r\n\x1a\n"

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
    raw = b"\x00" + b"\x00\x00\x00\x00"
    idat = chunk(b"IDAT", zlib.compress(raw))
    iend = chunk(b"IEND", b"")
    (ATTACHMENTS / "1x1.png").write_bytes(sig + ihdr + idat + iend)

    for size, name in [(10 * 1024, "10kib.bin"), (100 * 1024, "100kib.bin"), (1024 * 1024, "1mib.bin")]:
        random.seed(0xDEADBEEF ^ size)
        (ATTACHMENTS / name).write_bytes(
            bytes(random.randrange(256) for _ in range(size))
        )

    (ATTACHMENTS / "empty.dat").write_bytes(b"")
    (ATTACHMENTS / "unicode-café.txt").write_bytes(
        b"Testing non-ASCII filename handling.\n"
    )

    # Mock PEM-shaped attachment — deliberately NOT a usable crypto key.
    # We never parse this; tests only verify byte-exact preservation.
    (ATTACHMENTS / "mock-key.pem").write_bytes(
        b"# FIXTURE TEST KEY PLACEHOLDER - DO NOT USE\n"
        b"-----BEGIN PRIVATE KEY-----\n"
        b"MC4CAQAwBQYDK2VwBCIEIEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        b"-----END PRIVATE KEY-----\n"
    )
    log("attachments regenerated")


# -----------------------------------------------------------------------------
# KeePassXC CLI generators
# -----------------------------------------------------------------------------

def _kpxc_create_db(path: Path, password: str, keyfile: Path | None = None) -> None:
    """Create an empty database with the given credentials."""
    if path.exists():
        path.unlink()
    args = ["db-create", str(path), "-p", "-t", "100", "-q"]
    if keyfile is not None:
        args += ["--set-key-file", str(keyfile)]
    run_cli(*args, stdin=f"{password}\n{password}\n")


def _kpxc_add_entry(db: Path, password: str, entry: EntrySpec, keyfile: Path | None = None) -> None:
    """Add one entry to an open database."""
    args = ["add", str(db), entry.path, "-u", entry.username, "--url", entry.url, "-p", "-q"]
    if entry.notes:
        args += ["--notes", entry.notes]
    if keyfile is not None:
        args += ["--key-file", str(keyfile)]
    # Password prompt reads from stdin; db-unlock password comes first.
    run_cli(*args, stdin=f"{password}\n{entry.password}\n")


def _kpxc_mkdir(db: Path, password: str, group_path: str, keyfile: Path | None = None) -> None:
    args = ["mkdir", str(db), group_path, "-q"]
    if keyfile is not None:
        args += ["--key-file", str(keyfile)]
    run_cli(*args, stdin=f"{password}\n")


def _kpxc_attach(db: Path, password: str, entry_path: str, name: str, src: Path,
                 keyfile: Path | None = None) -> None:
    args = ["attachment-import", str(db), entry_path, name, str(src), "-q"]
    if keyfile is not None:
        args += ["--key-file", str(keyfile)]
    run_cli(*args, stdin=f"{password}\n")


def gen_keepassxc_kdbx3_minimal() -> None:
    """One entry, one group, no attachments. Smallest possible KDBX4."""
    name = "kdbx3-minimal"
    db = KEEPASSXC_DIR / f"{name}.kdbx"
    pw = "test-minimal-001"
    KEEPASSXC_DIR.mkdir(parents=True, exist_ok=True)

    _kpxc_create_db(db, pw)
    entries = [EntrySpec(
        path="/Contoso Mail",
        title="Contoso Mail",
        username="alice@example.com",
        url="https://mail.contoso.example",
        password="p4ssw0rd-minimal-01",
    )]
    for e in entries:
        _kpxc_add_entry(db, pw, e)

    _write_sidecar_for_kpxc(db, name, pw, entries, [], "Smallest KDBX3 fixture — one entry, default root group.")
    log(f"wrote {name}")


def gen_keepassxc_kdbx3_basic() -> None:
    """Typical small vault: a few entries across two groups."""
    name = "kdbx3-basic"
    db = KEEPASSXC_DIR / f"{name}.kdbx"
    pw = "test-basic-002"

    _kpxc_create_db(db, pw)
    for g in ("Work", "Personal"):
        _kpxc_mkdir(db, pw, f"/{g}")

    entries = [
        EntrySpec("/Work/Contoso Mail",       "Contoso Mail",       "alice@example.com",   "https://mail.contoso.example",   "p4ss-work-01", notes="Primary work email.", tags=["work", "email"]),
        EntrySpec("/Work/Fabrikam VPN",       "Fabrikam VPN",       "bob@example.org",     "https://vpn.fabrikam.example",   "p4ss-work-02", tags=["work", "vpn"]),
        EntrySpec("/Work/Adventure Works",    "Adventure Works",    "charlie@example.com", "https://adventure-works.example","p4ss-work-03"),
        EntrySpec("/Personal/Acme Banking",   "Acme Banking",       "dave@example.net",    "https://bank.acme.example",      "p4ss-pers-01", tags=["personal", "banking"]),
        EntrySpec("/Personal/Acme Cloud",     "Acme Cloud",         "eve@example.net",     "https://cloud.acme.example",     "p4ss-pers-02", tags=["personal"]),
        EntrySpec("/Personal/Tailspin Toys",  "Tailspin Toys",      "alice@example.com",   "https://toys.tailspin.example",  "p4ss-pers-03"),
    ]
    for e in entries:
        _kpxc_add_entry(db, pw, e)

    _write_sidecar_for_kpxc(db, name, pw, entries, ["Work", "Personal"],
                            "Typical small vault: six entries across Work and Personal groups. "
                            "Covers basic field types, tags, and notes.")
    log(f"wrote {name}")


def gen_keepassxc_kdbx3_keyfile() -> None:
    """Password + keyfile combo. Keyfile is a 128-byte random blob (deterministic)."""
    name = "kdbx3-keyfile"
    db = KEEPASSXC_DIR / f"{name}.kdbx"
    keyfile = KEEPASSXC_DIR / f"{name}.key"
    pw = "test-keyfile-003"

    # Deterministic keyfile content
    import random
    random.seed(0xC0FFEE)
    keyfile.write_bytes(bytes(random.randrange(256) for _ in range(128)))

    _kpxc_create_db(db, pw, keyfile=keyfile)
    entries = [
        EntrySpec("/Contoso Mail", "Contoso Mail", "alice@example.com",
                  "https://mail.contoso.example", "p4ss-kf-01"),
        EntrySpec("/Fabrikam VPN", "Fabrikam VPN", "bob@example.org",
                  "https://vpn.fabrikam.example", "p4ss-kf-02"),
    ]
    for e in entries:
        _kpxc_add_entry(db, pw, e, keyfile=keyfile)

    _write_sidecar_for_kpxc(db, name, pw, entries, [],
                            "KDBX4 secured with password + keyfile. Tests composite-key derivation.",
                            keyfile=keyfile)
    log(f"wrote {name}")


def gen_keepassxc_kdbx3_attachments() -> None:
    """Attachments of various sizes — covers binary pool edge cases."""
    name = "kdbx3-attachments"
    db = KEEPASSXC_DIR / f"{name}.kdbx"
    pw = "test-att-004"

    _kpxc_create_db(db, pw)

    att_entries = [
        ("/Small Attachments", "Small Attachments", [
            ("hello.txt",         ATTACHMENTS / "hello.txt"),
            ("1x1.png",           ATTACHMENTS / "1x1.png"),
            ("empty.dat",         ATTACHMENTS / "empty.dat"),
            ("unicode-café.txt",  ATTACHMENTS / "unicode-café.txt"),
        ]),
        ("/Medium Attachment", "Medium Attachment", [
            ("10kib.bin",   ATTACHMENTS / "10kib.bin"),
            ("100kib.bin",  ATTACHMENTS / "100kib.bin"),
        ]),
        ("/Large Attachment", "Large Attachment", [
            ("1mib.bin",    ATTACHMENTS / "1mib.bin"),
        ]),
        ("/Key Attachment", "Key Attachment", [
            ("mock-key.pem", ATTACHMENTS / "mock-key.pem"),
        ]),
    ]

    entries = []
    for path, title, atts in att_entries:
        e = EntrySpec(path=path, title=title, username="alice@example.com",
                      url="https://example.com", password="p4ss-att",
                      attachments={n: src for n, src in atts})
        _kpxc_add_entry(db, pw, e)
        for att_name, src in atts:
            _kpxc_attach(db, pw, path, att_name, src)
        entries.append(e)

    _write_sidecar_for_kpxc(db, name, pw, entries, [],
                            "Attachments of varying sizes including 0-byte, tiny, medium, "
                            "1 MiB (crosses KDBX4 HMAC block boundary), and non-ASCII filename.")
    log(f"wrote {name}")


def gen_keepassxc_kdbx3_unicode() -> None:
    """Unicode throughout: titles, usernames, notes, group names, tags."""
    name = "kdbx3-unicode"
    db = KEEPASSXC_DIR / f"{name}.kdbx"
    pw = "tëst-üni-005"

    _kpxc_create_db(db, pw)
    for g in ("Работа", "個人用", "Café"):
        _kpxc_mkdir(db, pw, f"/{g}")

    entries = [
        EntrySpec("/Работа/Электронная почта",
                  "Электронная почта",
                  "алиса@example.com",
                  "https://почта.example",
                  "пароль-01",
                  notes="Кириллица в заметках.",
                  tags=["работа", "почта"]),
        EntrySpec("/個人用/銀行",
                  "銀行",
                  "テスト@example.org",
                  "https://銀行.example",
                  "パスワード-02",
                  notes="日本語のノート。",
                  tags=["個人", "銀行"]),
        EntrySpec("/Café/Ωmega Service",
                  "Ωmega Service",
                  "βeta@example.net",
                  "https://ωmega.example",
                  "π4ssωrd-03",
                  notes="Ελληνικά σημείωση.",
                  tags=["café", "greek"]),
        EntrySpec("/Emoji Test 🔐",
                  "Emoji Test 🔐",
                  "🔑@example.com",
                  "https://🌐.example",
                  "p4ss-🔒-04",
                  notes="Includes 4-byte UTF-8 and emoji 🎉.",
                  tags=["emoji", "4-byte"]),
    ]
    for e in entries:
        _kpxc_add_entry(db, pw, e)

    _write_sidecar_for_kpxc(db, name, pw, entries, ["Работа", "個人用", "Café"],
                            "Unicode throughout: Cyrillic, Japanese, Greek, emoji (4-byte UTF-8). "
                            "Tests encoding correctness in every XML position.")
    log(f"wrote {name}")


def gen_keepassxc_kdbx3_deep_groups() -> None:
    """Deeply nested group hierarchy."""
    name = "kdbx3-deep-groups"
    db = KEEPASSXC_DIR / f"{name}.kdbx"
    pw = "test-deep-006"

    _kpxc_create_db(db, pw)

    group_paths = [
        "/Level1",
        "/Level1/Level2",
        "/Level1/Level2/Level3",
        "/Level1/Level2/Level3/Level4",
        "/Level1/Level2/Level3/Level4/Level5",
        "/Parallel",
        "/Parallel/ChildA",
        "/Parallel/ChildB",
    ]
    for g in group_paths:
        _kpxc_mkdir(db, pw, g)

    entries = [
        EntrySpec("/Level1/Level2/Level3/Level4/Level5/Deep Entry",
                  "Deep Entry", "alice@example.com",
                  "https://deep.example", "p4ss-deep-01",
                  notes="Entry at depth 5."),
        EntrySpec("/Parallel/ChildA/Sibling Entry",
                  "Sibling Entry", "bob@example.com",
                  "https://parallel.example", "p4ss-sibling-02"),
        EntrySpec("/Root Entry",
                  "Root Entry", "charlie@example.com",
                  "https://root.example", "p4ss-root-03"),
    ]
    for e in entries:
        _kpxc_add_entry(db, pw, e)

    _write_sidecar_for_kpxc(db, name, pw, entries, group_paths,
                            "Deeply-nested groups (5 levels) plus parallel branches. "
                            "Tests group-tree traversal and path resolution.")
    log(f"wrote {name}")


def _write_sidecar_for_kpxc(db: Path, name: str, password: str,
                            entries: list[EntrySpec], group_paths: list[str],
                            description: str, keyfile: Path | None = None) -> None:
    """Common sidecar-writing logic for keepassxc-cli fixtures."""
    # Use pykeepass to verify the generated DB and populate the sidecar with
    # the actual UUIDs/timestamps as parsed.
    from pykeepass import PyKeePass
    kp = PyKeePass(
        filename=str(db),
        password=password,
        keyfile=str(keyfile) if keyfile else None,
    )

    sidecar_entries = []
    for e in kp.entries:
        parent_path = e.parentgroup.path if e.parentgroup else []
        sidecar_entries.append({
            "group": "/" + "/".join(parent_path) if parent_path else "/",
            "title": e.title or "",
            "username": e.username or "",
            "url": e.url or "",
            "notes": e.notes or "",
            "password_length": len(e.password or ""),
            "tags": sorted(e.tags or []),
            "custom_field_count": len(e.custom_properties or {}),
            "attachment_count": len(e.attachments),
            "attachments": [
                {"filename": a.filename, "size": len(a.binary), "sha256": hashlib.sha256(a.binary).hexdigest()}
                for a in e.attachments
            ],
        })

    gen_el = kp.tree.find(".//Generator")
    sidecar = {
        "description": description,
        "format": "KDBX3",
        "source": "keepassxc-cli",
        "generated_by": "tests/fixtures/generate.py",
        "master_password": password,
        "key_file": f"{name}.key" if keyfile else None,
        "database_name": kp.root_group.name,
        "generator": gen_el.text if gen_el is not None else None,
        "entry_count": len(kp.entries),
        "group_count": len(kp.groups),
        "group_paths": sorted(group_paths),
        "entries": sorted(sidecar_entries, key=lambda x: (x["group"], x["title"])),
    }
    write_sidecar(db.with_suffix(".json"), sidecar)


# -----------------------------------------------------------------------------
# pykeepass generators — edge cases keepassxc-cli can't produce cleanly
# -----------------------------------------------------------------------------

def gen_pykeepass_history() -> None:
    """Entries with multiple history versions."""
    from pykeepass import create_database

    name = "history"
    db_path = PYKEEPASS_DIR / f"{name}.kdbx"
    pw = "test-hist-101"
    PYKEEPASS_DIR.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()

    kp = create_database(str(db_path), password=pw)
    root = kp.root_group

    # An entry modified multiple times, each edit retained in history.
    entry = kp.add_entry(root, title="Contoso Mail",
                         username="alice@example.com",
                         password="original-password-v1",
                         url="https://mail.contoso.example")
    kp.save()

    # Re-open, edit, save — repeated to build history.
    for i, new_pw in enumerate(["second-password-v2", "third-password-v3", "fourth-password-v4"], start=1):
        kp = __import__("pykeepass").PyKeePass(str(db_path), password=pw)
        e = kp.find_entries(title="Contoso Mail", first=True)
        e.save_history()              # preserves the current version into history
        e.password = new_pw
        e.notes = f"Revision {i + 1}"
        kp.save()

    # Final sidecar describes current state + history count.
    kp = __import__("pykeepass").PyKeePass(str(db_path), password=pw)
    e = kp.find_entries(title="Contoso Mail", first=True)

    write_sidecar(db_path.with_suffix(".json"), {
        "description": "Single entry with three historical versions (total revisions: 4).",
        "format": "KDBX4",
        "source": "pykeepass",
        "generated_by": "tests/fixtures/generate.py",
        "master_password": pw,
        "key_file": None,
        "entry_count": 1,
        "entries": [{
            "group": "",
            "title": e.title,
            "username": e.username,
            "url": e.url,
            "password_length": len(e.password),
            "history_count": len(e.history),
        }],
    })
    log(f"wrote pykeepass/{name}")


def gen_pykeepass_recycle() -> None:
    """Recycle bin with a deleted entry and a deleted group."""
    from pykeepass import create_database, PyKeePass

    name = "recycle"
    db_path = PYKEEPASS_DIR / f"{name}.kdbx"
    pw = "test-recycle-102"
    if db_path.exists():
        db_path.unlink()

    kp = create_database(str(db_path), password=pw)
    root = kp.root_group

    # Create structure, then delete some of it into the recycle bin.
    g = kp.add_group(root, "Soon-To-Be-Deleted-Group")
    kp.add_entry(g, title="Entry Inside Doomed Group", username="alice@example.com",
                 password="will-be-trashed", url="https://example.com")
    kp.add_entry(root, title="Standalone Entry", username="bob@example.org",
                 password="also-doomed", url="https://example.org")
    kp.add_entry(root, title="Surviving Entry", username="charlie@example.net",
                 password="kept", url="https://example.net")
    kp.save()

    # Re-open and move two items to the recycle bin (pykeepass creates it on demand).
    kp = PyKeePass(str(db_path), password=pw)
    kp.trash_entry(kp.find_entries(title="Standalone Entry", first=True))
    kp.trash_group(kp.find_groups(name="Soon-To-Be-Deleted-Group", first=True))
    kp.save()

    kp = PyKeePass(str(db_path), password=pw)
    write_sidecar(db_path.with_suffix(".json"), {
        "description": "Populated recycle bin with one entry and one group (containing its own entry).",
        "format": "KDBX4",
        "source": "pykeepass",
        "generated_by": "tests/fixtures/generate.py",
        "master_password": pw,
        "key_file": None,
        "entry_count": len(kp.entries),
        "group_count": len(kp.groups),
        "recycle_bin_present": kp.recyclebin_group is not None,
        "recycle_bin_entries": sorted(
            e.title for e in (kp.recyclebin_group.entries if kp.recyclebin_group else [])
        ),
    })
    log(f"wrote pykeepass/{name}")


def gen_pykeepass_custom_fields() -> None:
    """Protected + unprotected custom fields."""
    from pykeepass import create_database, PyKeePass

    name = "custom-fields"
    db_path = PYKEEPASS_DIR / f"{name}.kdbx"
    pw = "test-custom-104"
    if db_path.exists():
        db_path.unlink()

    kp = create_database(str(db_path), password=pw)
    e = kp.add_entry(kp.root_group, title="Contoso Multi-Field",
                     username="alice@example.com",
                     password="p4ss-custom", url="https://example.com")
    # Unprotected custom fields
    e.set_custom_property("Recovery Code", "RC-1234-5678-9ABC", protect=False)
    e.set_custom_property("API Key ID", "api-key-id-ak23901", protect=False)
    # Protected custom fields
    e.set_custom_property("API Secret", "api-secret-xyz-abc-protected", protect=True)
    e.set_custom_property("PIN", "0000", protect=True)
    kp.save()

    kp = PyKeePass(str(db_path), password=pw)
    e = kp.entries[0]
    write_sidecar(db_path.with_suffix(".json"), {
        "description": "Entry with mix of protected and unprotected custom fields.",
        "format": "KDBX4",
        "source": "pykeepass",
        "generated_by": "tests/fixtures/generate.py",
        "master_password": pw,
        "key_file": None,
        "entry_count": 1,
        "custom_fields": sorted([
            {"key": k, "value_length": len(v),
             "protected": k in [p for p in e.custom_properties if e.is_custom_property_protected(p)]}
            for k, v in e.custom_properties.items()
        ], key=lambda x: x["key"]),
    })
    log(f"wrote pykeepass/{name}")


def gen_pykeepass_large() -> None:
    """Large vault — 1000 entries. Tests scaling + stable parse time."""
    from pykeepass import create_database, PyKeePass

    name = "large"
    db_path = PYKEEPASS_DIR / f"{name}.kdbx"
    pw = "test-large-105"
    if db_path.exists():
        db_path.unlink()

    kp = create_database(str(db_path), password=pw)
    for i in range(1000):
        person = PEOPLE[i % len(PEOPLE)]
        svc, url = SERVICES[i % len(SERVICES)]
        kp.add_entry(
            kp.root_group,
            title=f"{svc} #{i:04d}",
            username=f"{person}+{i}@example.com",
            password=f"p4ss-large-{i:04d}",
            url=url,
        )
    kp.save()

    kp = PyKeePass(str(db_path), password=pw)
    write_sidecar(db_path.with_suffix(".json"), {
        "description": "1,000 entries — scaling / parse-time regression guard.",
        "format": "KDBX4",
        "source": "pykeepass",
        "generated_by": "tests/fixtures/generate.py",
        "master_password": pw,
        "key_file": None,
        "entry_count": len(kp.entries),
        "expected_entry_count": 1000,
    })
    log(f"wrote pykeepass/{name}")


# -----------------------------------------------------------------------------
# Malformed fixtures — negative tests
# -----------------------------------------------------------------------------

def gen_malformed_truncated() -> None:
    """A valid KDBX4 file truncated partway through the header."""
    MALFORMED_DIR.mkdir(parents=True, exist_ok=True)
    source = KEEPASSXC_DIR / "kdbx3-minimal.kdbx"
    if not source.exists():
        log("skipping truncated — minimal fixture not generated yet")
        return
    data = source.read_bytes()
    # Truncate to 64 bytes — past the magic but mid-TLV.
    (MALFORMED_DIR / "truncated.kdbx").write_bytes(data[:64])
    write_sidecar(MALFORMED_DIR / "truncated.json", {
        "description": "Truncated at 64 bytes — past the magic, mid-header-TLV.",
        "format": "KDBX4",
        "source": "synthetic",
        "generated_by": "tests/fixtures/generate.py",
        "expected_error": "truncated_or_malformed_header",
        "source_fixture": "keepassxc/kdbx3-minimal.kdbx",
    })
    log("wrote malformed/truncated")


def gen_malformed_bad_magic() -> None:
    """First four bytes munged — should fail the magic check."""
    MALFORMED_DIR.mkdir(parents=True, exist_ok=True)
    source = KEEPASSXC_DIR / "kdbx3-minimal.kdbx"
    if not source.exists():
        log("skipping bad-magic — minimal fixture not generated yet")
        return
    data = bytearray(source.read_bytes())
    data[0:4] = b"\x00\x00\x00\x00"
    (MALFORMED_DIR / "bad-magic.kdbx").write_bytes(bytes(data))
    write_sidecar(MALFORMED_DIR / "bad-magic.json", {
        "description": "First 4 bytes zeroed — magic-bytes check must reject.",
        "format": "KDBX4",
        "source": "synthetic",
        "generated_by": "tests/fixtures/generate.py",
        "expected_error": "bad_magic",
        "source_fixture": "keepassxc/kdbx3-minimal.kdbx",
    })
    log("wrote malformed/bad-magic")


def gen_malformed_hmac_fail() -> None:
    """Last byte of the file flipped — HMAC on final block must fail."""
    MALFORMED_DIR.mkdir(parents=True, exist_ok=True)
    source = KEEPASSXC_DIR / "kdbx3-minimal.kdbx"
    if not source.exists():
        log("skipping hmac-fail — minimal fixture not generated yet")
        return
    data = bytearray(source.read_bytes())
    data[-1] ^= 0xFF
    (MALFORMED_DIR / "hmac-fail.kdbx").write_bytes(bytes(data))
    write_sidecar(MALFORMED_DIR / "hmac-fail.json", {
        "description": "Final byte XOR'd with 0xFF — KDBX4 block HMAC verification must reject.",
        "format": "KDBX4",
        "source": "synthetic",
        "generated_by": "tests/fixtures/generate.py",
        "expected_error": "hmac_mismatch",
        "source_fixture": "keepassxc/kdbx3-minimal.kdbx",
    })
    log("wrote malformed/hmac-fail")


# -----------------------------------------------------------------------------
# Orchestration
# -----------------------------------------------------------------------------

GENERATORS: dict[str, list[Callable[[], None]]] = {
    "attachments": [generate_attachments],
    "keepassxc": [
        gen_keepassxc_kdbx3_minimal,
        gen_keepassxc_kdbx3_basic,
        gen_keepassxc_kdbx3_keyfile,
        gen_keepassxc_kdbx3_attachments,
        gen_keepassxc_kdbx3_unicode,
        gen_keepassxc_kdbx3_deep_groups,
    ],
    "pykeepass": [
        gen_pykeepass_history,
        gen_pykeepass_recycle,
        gen_pykeepass_custom_fields,
        gen_pykeepass_large,
    ],
    "malformed": [
        gen_malformed_truncated,
        gen_malformed_bad_magic,
        gen_malformed_hmac_fail,
    ],
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--only", choices=list(GENERATORS), action="append",
                        help="Run only these categories (may be repeated)")
    args = parser.parse_args()

    categories = args.only or list(GENERATORS)
    if "keepassxc" in categories:
        ensure_keepassxc_available()

    # Order matters — malformed depends on keepassxc fixtures already existing.
    order = ["attachments", "keepassxc", "pykeepass", "malformed"]
    for cat in order:
        if cat not in categories:
            continue
        log(f"=== {cat} ===")
        for fn in GENERATORS[cat]:
            fn()

    log("done")


if __name__ == "__main__":
    main()
