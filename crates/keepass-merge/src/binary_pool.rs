//! Binary-pool reconciliation between two vaults.
//!
//! KDBX stores attachment payloads in a per-vault [`Binary`] pool;
//! [`Attachment::ref_id`] is an index into that pool. When merge moves
//! an entry from `remote` into `local` (via overwrite, history-merge,
//! or insertion), the entry's `ref_id` values are indices into
//! `remote.binaries` and become silently incorrect — or out-of-bounds —
//! when the entry is installed in `local` without remapping.
//!
//! [`BinaryPoolRemap`] is the small piece of plumbing that fixes this:
//! it owns `&mut local.binaries` plus a read-only `&remote.binaries`,
//! and translates a remote `ref_id` into a local `ref_id`, importing
//! the binary into `local.binaries` (with content-hash dedup) on
//! demand. A remap cache shared across calls means many entries
//! referencing the same remote binary all converge on the same local
//! index — both correctness (no accidental divergence) and economy
//! (one append per distinct binary).
//!
//! Scope: this module fixes the latent gap that affects every
//! cross-side attachment carry-over today (auto-merge buckets included).
//! The attachment-conflict resolution surface (per-attachment caller
//! choice with rename-on-collision) lives in a later slice.

use std::collections::HashMap;

use keepass_core::model::{Attachment, Binary};
use sha2::{Digest, Sha256};

/// Translates remote-vault [`Attachment::ref_id`] values to indices
/// into `local.binaries`, importing remote binaries on demand.
///
/// Dedup is by SHA-256 of the decoded payload bytes plus the
/// `protected` flag — two binaries with identical bytes but differing
/// `protected` are kept distinct so the round-trip preserves the
/// on-disk inner-header flag.
///
/// **Idempotency contract:** [`Self::rebind`] mutates `ref_id` values
/// from "remote-pool index" to "local-pool index". A second call on
/// the same attachments would interpret the now-local indices as
/// remote indices and produce wrong results. Call exactly once per
/// remote-sourced entry, before installing into `local`.
pub(crate) struct BinaryPoolRemap<'a> {
    local_binaries: &'a mut Vec<Binary>,
    remote_binaries: &'a [Binary],
    /// remote ref_id → local ref_id, populated lazily.
    cache: HashMap<u32, u32>,
    /// Local-pool dedup index by `(sha256, protected)`, populated on
    /// first need. Tracks every binary that exists in `local_binaries`
    /// — initial contents plus anything we've appended.
    local_index: Option<HashMap<([u8; 32], bool), u32>>,
}

impl<'a> BinaryPoolRemap<'a> {
    pub(crate) fn new(local_binaries: &'a mut Vec<Binary>, remote_binaries: &'a [Binary]) -> Self {
        Self {
            local_binaries,
            remote_binaries,
            cache: HashMap::new(),
            local_index: None,
        }
    }

    /// Rewrite every `ref_id` in `attachments` from a remote-pool index
    /// to the corresponding local-pool index, importing as needed.
    ///
    /// Attachments whose `ref_id` is out of bounds in `remote_binaries`
    /// are left unchanged. That mirrors the existing apply-step posture
    /// of skipping malformed records rather than failing the whole
    /// merge — a corrupt ref in one entry shouldn't block the rest of
    /// the merge from succeeding. The unchanged ref will then either
    /// happen to address a valid local binary (rare) or surface as a
    /// read-time skip downstream (matches today's behaviour).
    pub(crate) fn rebind(&mut self, attachments: &mut [Attachment]) {
        for att in attachments {
            if let Some(new_id) = self.translate(att.ref_id) {
                att.ref_id = new_id;
            }
        }
    }

    fn translate(&mut self, remote_ref_id: u32) -> Option<u32> {
        if let Some(&hit) = self.cache.get(&remote_ref_id) {
            return Some(hit);
        }
        let idx = usize::try_from(remote_ref_id).ok()?;
        let remote_bin = self.remote_binaries.get(idx)?;
        let key = (sha256(&remote_bin.data), remote_bin.protected);

        // Build the local index lazily — many merges have zero
        // remote-sourced attachments and shouldn't pay the cost.
        if self.local_index.is_none() {
            let mut idx_map = HashMap::with_capacity(self.local_binaries.len());
            for (i, b) in self.local_binaries.iter().enumerate() {
                let k = (sha256(&b.data), b.protected);
                // First occurrence wins; later identical entries (legal
                // per KDBX, just refcount-redundant) keep their slot.
                idx_map.entry(k).or_insert_with(|| u32_from_usize(i));
            }
            self.local_index = Some(idx_map);
        }
        let local_index = self.local_index.as_mut().expect("just populated above");

        let local_id = if let Some(&existing) = local_index.get(&key) {
            existing
        } else {
            let new_idx = u32_from_usize(self.local_binaries.len());
            self.local_binaries.push(remote_bin.clone());
            local_index.insert(key, new_idx);
            new_idx
        };
        self.cache.insert(remote_ref_id, local_id);
        Some(local_id)
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

fn u32_from_usize(n: usize) -> u32 {
    // Binary-pool indices have to fit in `u32` because the on-disk
    // KDBX `<Binary Ref="N"/>` attribute is a `u32`. Pools approaching
    // that size are not a realistic vault — this is a debug-time
    // sanity check, not a hot path.
    debug_assert!(
        u32::try_from(n).is_ok(),
        "binary-pool index exceeds u32::MAX — refusing to truncate",
    );
    u32::try_from(n).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::BinaryPoolRemap;
    use keepass_core::model::{Attachment, Binary};

    fn bin(data: &[u8], protected: bool) -> Binary {
        Binary::new(data.to_vec(), protected)
    }

    fn att(name: &str, ref_id: u32) -> Attachment {
        Attachment::new(name, ref_id)
    }

    #[test]
    fn imports_remote_binary_into_empty_local_pool() {
        let mut local = Vec::new();
        let remote = vec![bin(b"hello", false)];
        let mut remap = BinaryPoolRemap::new(&mut local, &remote);
        let mut atts = vec![att("greeting.txt", 0)];
        remap.rebind(&mut atts);
        assert_eq!(atts[0].ref_id, 0);
        assert_eq!(local.len(), 1);
        assert_eq!(local[0].data, b"hello");
    }

    #[test]
    fn dedups_against_existing_local_binary_by_content() {
        let mut local = vec![bin(b"hello", false)];
        let remote = vec![bin(b"hello", false)];
        let mut remap = BinaryPoolRemap::new(&mut local, &remote);
        let mut atts = vec![att("greeting.txt", 0)];
        remap.rebind(&mut atts);
        assert_eq!(atts[0].ref_id, 0, "should reuse existing local index");
        assert_eq!(local.len(), 1, "pool must not grow");
    }

    #[test]
    fn protected_flag_distinguishes_dedup() {
        let mut local = vec![bin(b"x", false)];
        let remote = vec![bin(b"x", true)];
        let mut remap = BinaryPoolRemap::new(&mut local, &remote);
        let mut atts = vec![att("x", 0)];
        remap.rebind(&mut atts);
        assert_eq!(atts[0].ref_id, 1, "different protected flag → new slot");
        assert_eq!(local.len(), 2);
        assert!(local[1].protected);
    }

    #[test]
    fn cache_makes_repeated_translations_consistent() {
        let mut local = Vec::new();
        let remote = vec![bin(b"a", false), bin(b"b", false)];
        let mut remap = BinaryPoolRemap::new(&mut local, &remote);
        let mut first = vec![att("a", 0), att("b", 1)];
        let mut second = vec![att("a-again", 0), att("b-again", 1)];
        remap.rebind(&mut first);
        remap.rebind(&mut second);
        assert_eq!(first[0].ref_id, second[0].ref_id);
        assert_eq!(first[1].ref_id, second[1].ref_id);
        assert_eq!(local.len(), 2, "each distinct remote binary imported once");
    }

    #[test]
    fn out_of_bounds_remote_ref_id_left_unchanged() {
        let mut local = Vec::new();
        let remote = vec![bin(b"only", false)];
        let mut remap = BinaryPoolRemap::new(&mut local, &remote);
        let mut atts = vec![att("dangling", 99)];
        remap.rebind(&mut atts);
        assert_eq!(atts[0].ref_id, 99, "malformed ref left as-is");
        assert!(local.is_empty(), "no binary imported for bad ref");
    }

    #[test]
    fn local_pool_index_uses_first_occurrence_when_duplicates_present() {
        // KDBX allows duplicate binaries in the pool (refcount-redundant
        // but legal). Dedup should map to the first occurrence so the
        // import path doesn't append a third copy.
        let mut local = vec![bin(b"dup", false), bin(b"dup", false)];
        let remote = vec![bin(b"dup", false)];
        let mut remap = BinaryPoolRemap::new(&mut local, &remote);
        let mut atts = vec![att("d", 0)];
        remap.rebind(&mut atts);
        assert_eq!(atts[0].ref_id, 0);
        assert_eq!(local.len(), 2, "no new append for content-dedup hit");
    }
}
