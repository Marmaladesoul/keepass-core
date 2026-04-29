//! Slice 6 — `EntryEditor::attach` / `detach` with refcounted
//! [`Vault::binaries`] pool management.
//!
//! Per MUTATION.md §"Slicing plan" slice 6. Two concerns:
//!
//! 1. **In-memory shared-binary semantics.** Attach the same bytes
//!    to two different entries → pool gains a single entry, both
//!    attachments share its index. Detach from one → pool keeps the
//!    binary because the second entry still references it. Detach
//!    from the second → pool shrinks.
//!
//! 2. **Round-trip through `save_to_bytes`.** Open a fixture, attach
//!    a binary to an entry, save, re-open, confirm both the entry's
//!    `<Binary>` reference and the inner-header binaries pool round-
//!    tripped — including for a *protected* attachment, which travels
//!    through the inner-stream cipher.

use chrono::{DateTime, Utc};
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Sealed};
use keepass_core::model::{FixedClock, HistoryPolicy, NewEntry, NewGroup};
use std::fs;
use std::path::{Path, PathBuf};

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
}

fn kdbx4_basic() -> PathBuf {
    fixtures_root().join("kdbxweb/kdbx4-basic.kdbx")
}

fn password_from_sidecar(path: &Path) -> String {
    let sidecar = path.with_extension("json");
    let text = fs::read_to_string(sidecar).unwrap();
    text.split("\"master_password\"")
        .nth(1)
        .and_then(|s| s.split('"').nth(1))
        .unwrap()
        .to_owned()
}

#[test]
fn shared_binary_survives_one_detach_then_pool_shrinks_after_the_last() {
    // Mirrors the prompt's exact scenario: attach to A, attach same
    // bytes to B, detach from A → pool unchanged (still referenced
    // by B); detach from B → pool shrinks.
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());
    let at: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();

    let mut kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, Box::new(FixedClock(at)))
        .unwrap();

    let pool_before = kdbx.vault().binaries.len();
    let root = kdbx.vault().root.id;
    let id_a = kdbx.add_entry(root, NewEntry::new("A")).unwrap();
    let id_b = kdbx.add_entry(root, NewEntry::new("B")).unwrap();

    let payload = b"shared payload bytes".to_vec();

    // Attach the same bytes to both entries.
    kdbx.edit_entry(id_a, HistoryPolicy::NoSnapshot, |e| {
        e.attach("shared.bin", payload.clone(), false);
    })
    .unwrap();
    kdbx.edit_entry(id_b, HistoryPolicy::NoSnapshot, |e| {
        e.attach("shared.bin", payload.clone(), false);
    })
    .unwrap();

    // Pool grew by exactly one (dedup on content hash).
    assert_eq!(kdbx.vault().binaries.len(), pool_before + 1);
    let ref_a = kdbx
        .vault()
        .iter_entries()
        .find(|e| e.id == id_a)
        .and_then(|e| e.attachments.first())
        .map(|a| a.ref_id)
        .expect("A has the attachment");
    let ref_b = kdbx
        .vault()
        .iter_entries()
        .find(|e| e.id == id_b)
        .and_then(|e| e.attachments.first())
        .map(|a| a.ref_id)
        .expect("B has the attachment");
    assert_eq!(ref_a, ref_b, "dedup must reuse the same pool index");

    // Detach from A: pool stays the same; B still references it.
    kdbx.edit_entry(id_a, HistoryPolicy::NoSnapshot, |e| {
        assert!(e.detach("shared.bin"));
    })
    .unwrap();
    assert_eq!(
        kdbx.vault().binaries.len(),
        pool_before + 1,
        "pool must not shrink while another entry still references the binary"
    );
    let still_b = kdbx
        .vault()
        .iter_entries()
        .find(|e| e.id == id_b)
        .and_then(|e| e.attachments.first())
        .map(|a| a.ref_id)
        .expect("B still has its attachment after A detaches");
    // The pool didn't shrink, so B's ref_id is unchanged.
    assert_eq!(still_b, ref_b);

    // Detach from B: now the last reference is gone → pool shrinks.
    kdbx.edit_entry(id_b, HistoryPolicy::NoSnapshot, |e| {
        assert!(e.detach("shared.bin"));
    })
    .unwrap();
    assert_eq!(
        kdbx.vault().binaries.len(),
        pool_before,
        "pool must shrink once the last reference detaches"
    );
}

#[test]
fn attach_then_save_round_trips_payload_and_protected_flag() {
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());
    let at: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();

    let mut kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, Box::new(FixedClock(at)))
        .unwrap();

    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("WithBinary")).unwrap();

    let plain_bytes = b"hello, plain attachment\n".to_vec();
    let secret_bytes = b"top-secret payload bytes\n".to_vec();

    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.attach("note.txt", plain_bytes.clone(), false);
        e.attach("secret.bin", secret_bytes.clone(), true);
    })
    .unwrap();

    let bytes = kdbx.save_to_bytes().unwrap();
    let reopened = Kdbx::<Sealed>::open_from_bytes(bytes)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(&composite)
        .unwrap();

    let after = reopened
        .vault()
        .iter_entries()
        .find(|e| e.id == id)
        .expect("entry survives round-trip");
    assert_eq!(after.attachments.len(), 2);

    // Resolve each attachment back through the binaries pool and
    // assert payload equality + protected-flag preservation.
    let resolve = |name: &str| -> (Vec<u8>, bool) {
        let att = after
            .attachments
            .iter()
            .find(|a| a.name == name)
            .expect("attachment by name");
        let bin = &reopened.vault().binaries[att.ref_id as usize];
        (bin.data.clone(), bin.protected)
    };
    assert_eq!(resolve("note.txt"), (plain_bytes, false));
    assert_eq!(resolve("secret.bin"), (secret_bytes, true));
}

#[test]
fn delete_entry_reaps_orphan_binaries_in_memory_and_on_disk() {
    // Pre-fix, `delete_entry` removed the entry but left its
    // attachment bytes parked in `vault.binaries`. The next
    // `save_to_bytes` then wrote those orphan bytes back to the new
    // file — a small but real privacy bug, since the user explicitly
    // asked us to forget the entry.
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());
    let at: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();

    let mut kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, Box::new(FixedClock(at)))
        .unwrap();

    let pool_before = kdbx.vault().binaries.len();
    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(root, NewEntry::new("DoomedAttachmentOwner"))
        .unwrap();

    let payload = b"bytes that must not survive deletion\n".to_vec();
    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.attach("doomed.bin", payload.clone(), false);
    })
    .unwrap();
    assert_eq!(kdbx.vault().binaries.len(), pool_before + 1);

    // Delete the entry — the only referent of the binary.
    kdbx.delete_entry(id).unwrap();
    assert_eq!(
        kdbx.vault().binaries.len(),
        pool_before,
        "in-memory pool must shrink once the last referent is deleted"
    );

    // Save + re-open round-trips a clean pool: the orphan bytes are
    // gone from the on-disk artefact too.
    let bytes = kdbx.save_to_bytes().unwrap();
    let reopened = Kdbx::<Sealed>::open_from_bytes(bytes)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(&composite)
        .unwrap();
    assert_eq!(
        reopened.vault().binaries.len(),
        pool_before,
        "on-disk pool must not carry the deleted entry's attachment bytes"
    );
    let payload_str = String::from_utf8(payload).unwrap();
    let any_match = reopened
        .vault()
        .binaries
        .iter()
        .any(|b| b.data == payload_str.as_bytes());
    assert!(
        !any_match,
        "deleted attachment bytes leaked into the reopened pool"
    );
}

#[test]
fn delete_group_reaps_attachments_owned_only_by_its_subtree() {
    // Same shape as `delete_entry_reaps_orphan_binaries_in_memory_and_on_disk`
    // but exercises the multi-entry, multi-attachment path through
    // `delete_group`. Worst-case for the pre-fix bug: a whole branch
    // of attachments orphaned in one go.
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());
    let at: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();

    let mut kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, Box::new(FixedClock(at)))
        .unwrap();

    let pool_before = kdbx.vault().binaries.len();
    let root = kdbx.vault().root.id;
    let doomed_group = kdbx
        .add_group(root, NewGroup::new("DoomedSubtree"))
        .unwrap();
    let id_a = kdbx.add_entry(doomed_group, NewEntry::new("A")).unwrap();
    let id_b = kdbx.add_entry(doomed_group, NewEntry::new("B")).unwrap();

    kdbx.edit_entry(id_a, HistoryPolicy::NoSnapshot, |e| {
        e.attach("a.bin", b"alpha bytes\n".to_vec(), false);
    })
    .unwrap();
    kdbx.edit_entry(id_b, HistoryPolicy::NoSnapshot, |e| {
        e.attach("b.bin", b"beta bytes\n".to_vec(), true);
    })
    .unwrap();
    assert_eq!(kdbx.vault().binaries.len(), pool_before + 2);

    kdbx.delete_group(doomed_group).unwrap();
    assert_eq!(
        kdbx.vault().binaries.len(),
        pool_before,
        "in-memory pool must shrink once the entire subtree is deleted"
    );
}
