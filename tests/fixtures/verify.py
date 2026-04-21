#!/usr/bin/env python3
"""
Verify every fixture matches its sidecar.

This is the Python equivalent of the Rust integration tests we'll write
once the `keepass-core` parser can open a file. It asserts every claim
in each sidecar against the actual vault contents as parsed by
`pykeepass`. If this passes, the corpus is internally consistent.

Usage:
    source .venv/bin/activate
    python3 tests/fixtures/verify.py

Exit code is non-zero on any mismatch.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from pykeepass import PyKeePass

HERE = Path(__file__).resolve().parent


def load_sidecar(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def verify_well_formed(sidecar_path: Path, errors: list[str]) -> None:
    """Open the fixture with pykeepass and assert every sidecar claim."""
    sidecar = load_sidecar(sidecar_path)
    kdbx_path = sidecar_path.with_suffix(".kdbx")

    if not kdbx_path.exists():
        errors.append(f"{sidecar_path}: no matching .kdbx")
        return

    pw = sidecar["master_password"]
    keyfile = sidecar.get("key_file")
    if keyfile is not None:
        keyfile = str(sidecar_path.parent / keyfile)

    try:
        kp = PyKeePass(str(kdbx_path), password=pw, keyfile=keyfile)
    except Exception as e:
        errors.append(f"{kdbx_path}: failed to open ({type(e).__name__}: {e})")
        return

    # Entry count
    expected_count = sidecar.get("entry_count")
    if expected_count is not None and len(kp.entries) != expected_count:
        errors.append(f"{kdbx_path}: entry_count {len(kp.entries)} != sidecar {expected_count}")

    # Group count (if claimed)
    expected_groups = sidecar.get("group_count")
    if expected_groups is not None and len(kp.groups) != expected_groups:
        errors.append(f"{kdbx_path}: group_count {len(kp.groups)} != sidecar {expected_groups}")

    # Entry-by-entry detail verification
    claimed = sidecar.get("entries")
    if claimed is not None and isinstance(claimed, list) and claimed and "title" in claimed[0]:
        actual_by_title = {e.title: e for e in kp.entries}
        for claim in claimed:
            title = claim["title"]
            entry = actual_by_title.get(title)
            if entry is None:
                errors.append(f"{kdbx_path}: missing claimed entry '{title}'")
                continue
            for field in ("username", "url", "notes"):
                want = claim.get(field)
                got = getattr(entry, field, None) or ""
                if want is not None and got != want:
                    errors.append(
                        f"{kdbx_path}: entry '{title}' {field} = {got!r}, sidecar says {want!r}"
                    )
            want_plen = claim.get("password_length")
            got_plen = len(entry.password or "")
            if want_plen is not None and got_plen != want_plen:
                errors.append(
                    f"{kdbx_path}: entry '{title}' password_length = {got_plen}, sidecar says {want_plen}"
                )
            want_att_count = claim.get("attachment_count")
            got_att_count = len(entry.attachments)
            if want_att_count is not None and got_att_count != want_att_count:
                errors.append(
                    f"{kdbx_path}: entry '{title}' attachment_count = {got_att_count}, sidecar says {want_att_count}"
                )
            # Per-attachment SHA-256
            for claim_att in claim.get("attachments", []) or []:
                got_att = next(
                    (a for a in entry.attachments if a.filename == claim_att["filename"]),
                    None,
                )
                if got_att is None:
                    errors.append(
                        f"{kdbx_path}: entry '{title}' missing attachment {claim_att['filename']!r}"
                    )
                    continue
                got_sha = hashlib.sha256(got_att.binary).hexdigest()
                if got_sha != claim_att["sha256"]:
                    errors.append(
                        f"{kdbx_path}: attachment {claim_att['filename']!r} sha256 = {got_sha}, "
                        f"sidecar says {claim_att['sha256']}"
                    )


def verify_malformed(sidecar_path: Path, errors: list[str]) -> None:
    """Malformed fixtures: assert they FAIL to open (the opposite of well-formed)."""
    sidecar = load_sidecar(sidecar_path)
    kdbx_path = sidecar_path.with_suffix(".kdbx")

    # Malformed sidecars don't have master passwords; try a dummy
    # (we expect opening to fail before any password check anyway for bad-magic/truncated).
    try:
        PyKeePass(str(kdbx_path), password="dummy")
    except Exception:
        return  # expected

    errors.append(
        f"{kdbx_path}: opened successfully but sidecar says it should fail "
        f"with '{sidecar.get('expected_error', 'any error')}'"
    )


def main() -> int:
    errors: list[str] = []
    for sidecar in sorted(HERE.rglob("*.json")):
        # Skip the Node generator's package metadata — it lives under .node/
        # which also holds node_modules/ with many unrelated .json files.
        if "/.node/" in str(sidecar) or "/node_modules/" in str(sidecar):
            continue
        if "/malformed/" in str(sidecar):
            verify_malformed(sidecar, errors)
        else:
            verify_well_formed(sidecar, errors)

    if errors:
        print(f"{len(errors)} verification errors:", file=sys.stderr)
        for err in errors:
            print(f"  {err}", file=sys.stderr)
        return 1

    print("all fixtures verified ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())
