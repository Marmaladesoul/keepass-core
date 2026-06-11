//! Throwaway test harness: set one entry's password in a KDBX file.
//!
//! Used to drive cross-device sync soak scenarios without a GUI — edit the
//! same entry to different values on two machines, let each side's file
//! watcher pick it up, and watch them reconcile. NOT a production tool.
//!
//! Usage:
//!   kdbx_edit <kdbx-path> <entry-title> <new-password>
//! The *vault* password is read from stdin (raw bytes; one trailing newline,
//! if present, is stripped). Password-only vaults (no keyfile).

use std::io::Read as _;

use keepass_core::CompositeKey;
use keepass_core::kdbx::Kdbx;
use keepass_core::model::{HistoryPolicy, NewEntry};
use secrecy::SecretString;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: kdbx_edit <kdbx-path> <entry-title> <new-password>  (vault pw on stdin)");
        std::process::exit(2);
    }
    let path = &args[1];
    let title = &args[2];
    let new_pw = &args[3];

    let mut vault_pw = Vec::new();
    std::io::stdin()
        .read_to_end(&mut vault_pw)
        .expect("read vault password from stdin");
    if vault_pw.last() == Some(&b'\n') {
        vault_pw.pop();
    }

    let composite = CompositeKey::from_password(&vault_pw);
    let mut kdbx = Kdbx::open(path)
        .expect("open kdbx")
        .read_header()
        .expect("read header")
        .unlock(&composite)
        .expect("unlock (wrong vault password?)");

    // Upsert by title: edit the existing entry, or create it (under root) if
    // there's no entry with that title yet.
    let existing = kdbx
        .vault()
        .iter_entries()
        .find(|e| e.title == *title)
        .map(|e| e.id);
    let id = if let Some(id) = existing {
        id
    } else {
        let root = kdbx.vault().root.id;
        let new_id = kdbx
            .add_entry(root, NewEntry::new(title.clone()))
            .expect("create entry");
        eprintln!("kdbx_edit: created new entry {title:?}");
        new_id
    };

    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_password(SecretString::from(new_pw.as_str()));
    })
    .expect("edit entry");

    let bytes = kdbx.save_to_bytes().expect("serialise kdbx");
    // Atomic write: temp file in the same dir + rename, so a concurrent reader
    // (the app's file watcher) sees either the old or new file, never a
    // half-written one.
    let tmp = format!("{path}.kdbxedit.tmp");
    std::fs::write(&tmp, &bytes).expect("write temp kdbx");
    std::fs::rename(&tmp, path).expect("atomic rename");
    eprintln!(
        "kdbx_edit: set password on {title:?} in {path} ({} bytes)",
        bytes.len()
    );
}
