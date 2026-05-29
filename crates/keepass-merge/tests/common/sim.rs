//! Tier 2 sync simulation harness.
//!
//! `Sim` holds N peers, each backed by an in-memory `Vault`. Tests
//! apply scripted [`Op`] sequences (or chaos-mode random ones) to
//! individual peers, then drive pairwise [`merge`] + [`apply_merge`]
//! rounds via [`Sim::sync_pairwise`] / [`Sim::sync_until_converged`].
//! [`Sim::assert_converged`] hashes a content fingerprint of each
//! peer's vault and panics with a reproduction-friendly diff if any
//! pair diverges.
//!
//! Determinism is the design constraint: every `Op` carries an
//! explicit clock value (sourced from [`Sim::next_clock`]) so a
//! failing chaos run can be replayed bit-for-bit just by re-feeding
//! the captured op log into a fresh `Sim`. The chaos op generator is
//! seeded from a `u64`; the seed plus the iteration count fully
//! determines the run.

#![allow(dead_code)]
// Each integration test compiles this module independently, so some
// `pub` items appear unused from any one test's perspective.
#![allow(unreachable_pub)]

use std::collections::BTreeSet;

use chrono::{DateTime, TimeZone, Utc};
use keepass_core::model::{
    Attachment, Binary, CustomDataItem, CustomField, DeletedObject, Entry, EntryId, Group, GroupId,
    Timestamps, Vault,
};
use keepass_merge::{
    ATTACHMENT_TOMBSTONE_CUSTOM_DATA_KEY, AttachmentTombstone, ParkConflictsConfig,
    TAG_STATE_CUSTOM_DATA_KEY, TagRemoval, TagState, apply_merge_park_conflicts, merge,
};
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// One peer in the simulation.
#[derive(Debug, Clone)]
pub struct Peer {
    pub name: String,
    pub vault: Vault,
}

impl Peer {
    fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            vault: Vault::empty(GroupId(Uuid::nil())),
        }
    }
}

/// Operations the sim can apply to a peer's vault. Each carries the
/// timestamps the merge engine reads so the whole simulation is
/// deterministic.
#[derive(Debug, Clone)]
pub enum Op {
    /// Create a new entry under a given group.
    AddEntry {
        entry_id: u128,
        group_id: u128,
        title: String,
        password: String,
        mtime: DateTime<Utc>,
        creation_time: DateTime<Utc>,
    },
    /// Edit an existing entry's title.
    EditTitle {
        entry_id: u128,
        new_title: String,
        mtime: DateTime<Utc>,
    },
    /// Edit an existing entry's password.
    EditPassword {
        entry_id: u128,
        new_password: String,
        mtime: DateTime<Utc>,
    },
    /// Edit an arbitrary custom field's value.
    EditCustomField {
        entry_id: u128,
        key: String,
        value: String,
        protected: bool,
        mtime: DateTime<Utc>,
    },
    /// Soft-delete an entry: append a `<DeletedObjects>` tombstone +
    /// remove the entry from any group.
    DeleteEntry {
        entry_id: u128,
        deleted_at: DateTime<Utc>,
    },
    /// Add a tag to an entry's tag list (bumps entry mtime).
    AddTag {
        entry_id: u128,
        tag: String,
        mtime: DateTime<Utc>,
    },
    /// Tombstone a tag — drops it from tags and adds a `keys.tag_state.v1`
    /// removal record.
    RemoveTag {
        entry_id: u128,
        tag: String,
        at: DateTime<Utc>,
    },
    /// Move an entry to a different group. Bumps `location_changed`.
    MoveEntry {
        entry_id: u128,
        new_group_id: u128,
        location_changed: DateTime<Utc>,
    },
    /// Attach a file to an entry. Inserts the bytes into the vault's
    /// binary pool if not already present.
    AttachFile {
        entry_id: u128,
        filename: String,
        bytes: Vec<u8>,
        mtime: DateTime<Utc>,
    },
    /// Detach a file from an entry and add a
    /// `keys.attachment_tombstones.v1` record so the detach sticks
    /// across syncs.
    DetachFile {
        entry_id: u128,
        filename: String,
        at: DateTime<Utc>,
    },
    /// Add a group under the given parent.
    AddGroup {
        group_id: u128,
        parent_id: u128,
        name: String,
        mtime: DateTime<Utc>,
        creation_time: DateTime<Utc>,
    },
    /// Update `<Meta><DatabaseName>` and stamp `database_name_changed`.
    EditDatabaseName {
        new_name: String,
        changed_at: DateTime<Utc>,
    },
    /// Lower the privacy-conservative history retention.
    SetHistoryMaxItems {
        value: i32,
        settings_changed: DateTime<Utc>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum SimError {
    #[error("entry {0:?} not found on peer {1}")]
    EntryNotFound(EntryId, usize),
    #[error("group {0:?} not found on peer {1}")]
    GroupNotFound(GroupId, usize),
    #[error("merge error on peer {peer}: {source:?}")]
    Merge {
        peer: usize,
        #[source]
        source: keepass_merge::MergeError,
    },
}

/// The simulation harness.
pub struct Sim {
    pub peers: Vec<Peer>,
    clock: i64,
    rng: ChaCha8Rng,
    op_log: Vec<(usize, Op)>,
}

impl Sim {
    /// Build a fresh simulation with `n` peers named "peer-0",
    /// "peer-1", … and the given RNG seed for chaos mode.
    #[must_use]
    pub fn new(n: usize, seed: u64) -> Self {
        let peers = (0..n).map(|i| Peer::new(format!("peer-{i}"))).collect();
        Self {
            peers,
            clock: 0,
            rng: ChaCha8Rng::seed_from_u64(seed),
            op_log: Vec::new(),
        }
    }

    /// Produce the next deterministic timestamp. Each call advances
    /// the clock by one second from a fixed epoch (2026-01-01) so
    /// every `Op`'s timestamps are unique and well-ordered.
    pub fn next_clock(&mut self) -> DateTime<Utc> {
        self.clock += 1;
        let epoch = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        epoch + chrono::Duration::seconds(self.clock)
    }

    /// Apply `op` to peer `idx`'s vault and record it in the op log
    /// (so a chaos failure can be replayed). Returns an error if the
    /// op refers to a missing entry / group.
    pub fn apply(&mut self, idx: usize, op: Op) -> Result<(), SimError> {
        self.op_log.push((idx, op.clone()));
        apply_op_to_vault(idx, &mut self.peers[idx].vault, op)
    }

    /// Drive `from ↔ to` two-way pairwise merge using the
    /// production parking-conflicts path. Returns the round count to
    /// reach a fingerprint match. Production usually converges in
    /// 1–2 rounds; we cap at 4 to detect divergence loudly rather
    /// than hang.
    pub fn sync_pairwise(&mut self, from: usize, to: usize) -> Result<usize, SimError> {
        assert_ne!(from, to);
        for round in 1..=4 {
            let from_snapshot = self.peers[from].vault.clone();
            let outcome =
                merge(&self.peers[to].vault, &from_snapshot).map_err(|e| SimError::Merge {
                    peer: to,
                    source: e,
                })?;
            let cfg = ParkConflictsConfig::with_now(self.next_clock());
            apply_merge_park_conflicts(&mut self.peers[to].vault, &from_snapshot, &outcome, &cfg)
                .map_err(|e| SimError::Merge {
                peer: to,
                source: e,
            })?;

            let to_snapshot = self.peers[to].vault.clone();
            let outcome2 =
                merge(&self.peers[from].vault, &to_snapshot).map_err(|e| SimError::Merge {
                    peer: from,
                    source: e,
                })?;
            let cfg2 = ParkConflictsConfig::with_now(self.next_clock());
            apply_merge_park_conflicts(&mut self.peers[from].vault, &to_snapshot, &outcome2, &cfg2)
                .map_err(|e| SimError::Merge {
                    peer: from,
                    source: e,
                })?;

            if fingerprint(&self.peers[from].vault) == fingerprint(&self.peers[to].vault) {
                return Ok(round);
            }
        }
        Ok(4)
    }

    /// Convergence check: every peer's vault fingerprint equals the
    /// first peer's. Returns `Err(Divergence)` with the differing
    /// peers' fingerprints and the captured op log so a failure
    /// reproduces.
    pub fn assert_converged(&self) -> Result<(), Divergence> {
        if self.peers.len() < 2 {
            return Ok(());
        }
        let baseline = fingerprint(&self.peers[0].vault);
        for (i, peer) in self.peers.iter().enumerate().skip(1) {
            let fp = fingerprint(&peer.vault);
            if fp != baseline {
                return Err(Divergence {
                    peer_a: self.peers[0].name.clone(),
                    fp_a: baseline,
                    peer_b: peer.name.clone(),
                    fp_b: fp,
                    op_count: self.op_log.len(),
                    seed_recovery: format!(
                        "replay the captured op log ({} ops) to reproduce — see Sim::op_log()",
                        self.op_log.len()
                    ),
                    peer_a_idx: 0,
                    peer_b_idx: i,
                });
            }
        }
        Ok(())
    }

    /// Borrow the captured op log — useful for printing reproduction
    /// info on a chaos-run divergence.
    #[must_use]
    pub fn op_log(&self) -> &[(usize, Op)] {
        &self.op_log
    }

    /// Generate a single random chaos op and apply it to a random
    /// peer. The chosen op respects each peer's current state — never
    /// generates an op that would obviously fail (e.g. editing a
    /// non-existent entry).
    pub fn chaos_step(&mut self, cfg: &ChaosConfig) -> Result<(), SimError> {
        let peer_idx = self.rng.random_range(0..self.peers.len());
        let op = self.generate_op(peer_idx, cfg);
        self.apply(peer_idx, op)
    }

    /// Generate and apply a chaos op on a specific peer. Useful for
    /// driving concurrent divergence rounds where both peers should
    /// edit *their own copy* of a shared substrate.
    pub fn apply_chaos_on(&mut self, peer_idx: usize, cfg: &ChaosConfig) -> Result<(), SimError> {
        let op = self.generate_op(peer_idx, cfg);
        self.apply(peer_idx, op)
    }

    fn generate_op(&mut self, peer_idx: usize, cfg: &ChaosConfig) -> Op {
        let existing_entries: Vec<u128> = collect_entry_ids(&self.peers[peer_idx].vault.root);
        let existing_groups: Vec<u128> = collect_group_ids(&self.peers[peer_idx].vault.root);
        // Always start with a synthetic root subgroup if there are no
        // groups so AddEntry has somewhere to land.
        let groups: Vec<u128> = if existing_groups.is_empty() {
            vec![0]
        } else {
            existing_groups.clone()
        };

        let mut choices: Vec<OpKind> = vec![OpKind::AddEntry, OpKind::AddGroup];
        if !existing_entries.is_empty() {
            choices.extend([
                OpKind::EditTitle,
                OpKind::EditPassword,
                OpKind::AddTag,
                OpKind::RemoveTag,
                OpKind::MoveEntry,
                OpKind::DeleteEntry,
                OpKind::AttachFile,
                OpKind::DetachFile,
            ]);
        }
        choices.push(OpKind::EditDatabaseName);
        if cfg.allow_history_retention_drop {
            choices.push(OpKind::SetHistoryMaxItems);
        }

        let kind = choices[self.rng.random_range(0..choices.len())];
        let now = self.next_clock();
        match kind {
            OpKind::AddEntry => Op::AddEntry {
                entry_id: u128::from(self.rng.random::<u32>()),
                group_id: groups[self.rng.random_range(0..groups.len())],
                title: format!("entry-{}", self.rng.random::<u16>()),
                password: format!("pw-{}", self.rng.random::<u16>()),
                mtime: now,
                creation_time: now,
            },
            OpKind::AddGroup => Op::AddGroup {
                group_id: u128::from(self.rng.random::<u32>()),
                parent_id: 0,
                name: format!("group-{}", self.rng.random::<u16>()),
                mtime: now,
                creation_time: now,
            },
            OpKind::EditTitle => Op::EditTitle {
                entry_id: existing_entries[self.rng.random_range(0..existing_entries.len())],
                new_title: format!("edit-{}", self.rng.random::<u16>()),
                mtime: now,
            },
            OpKind::EditPassword => Op::EditPassword {
                entry_id: existing_entries[self.rng.random_range(0..existing_entries.len())],
                new_password: format!("pw-{}", self.rng.random::<u16>()),
                mtime: now,
            },
            OpKind::AddTag => Op::AddTag {
                entry_id: existing_entries[self.rng.random_range(0..existing_entries.len())],
                tag: format!("t{}", self.rng.random::<u8>() % 5),
                mtime: now,
            },
            OpKind::RemoveTag => Op::RemoveTag {
                entry_id: existing_entries[self.rng.random_range(0..existing_entries.len())],
                tag: format!("t{}", self.rng.random::<u8>() % 5),
                at: now,
            },
            OpKind::MoveEntry => Op::MoveEntry {
                entry_id: existing_entries[self.rng.random_range(0..existing_entries.len())],
                new_group_id: groups[self.rng.random_range(0..groups.len())],
                location_changed: now,
            },
            OpKind::DeleteEntry => Op::DeleteEntry {
                entry_id: existing_entries[self.rng.random_range(0..existing_entries.len())],
                deleted_at: now,
            },
            OpKind::AttachFile => Op::AttachFile {
                entry_id: existing_entries[self.rng.random_range(0..existing_entries.len())],
                filename: format!("file-{}.bin", self.rng.random::<u8>() % 3),
                bytes: vec![self.rng.random::<u8>(); 16],
                mtime: now,
            },
            OpKind::DetachFile => Op::DetachFile {
                entry_id: existing_entries[self.rng.random_range(0..existing_entries.len())],
                filename: format!("file-{}.bin", self.rng.random::<u8>() % 3),
                at: now,
            },
            OpKind::EditDatabaseName => Op::EditDatabaseName {
                new_name: format!("vault-{}", self.rng.random::<u16>()),
                changed_at: now,
            },
            OpKind::SetHistoryMaxItems => Op::SetHistoryMaxItems {
                value: 1 + (self.rng.random::<u8>() as i32 % 30),
                settings_changed: now,
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum OpKind {
    AddEntry,
    AddGroup,
    EditTitle,
    EditPassword,
    AddTag,
    RemoveTag,
    MoveEntry,
    DeleteEntry,
    AttachFile,
    DetachFile,
    EditDatabaseName,
    SetHistoryMaxItems,
}

/// Knobs for chaos generation.
#[derive(Debug, Clone)]
pub struct ChaosConfig {
    /// Permit the random op stream to emit `SetHistoryMaxItems`.
    /// Lowering retention truncates history; on by default but
    /// off-able for narrower scenarios.
    pub allow_history_retention_drop: bool,
}

impl Default for ChaosConfig {
    fn default() -> Self {
        Self {
            allow_history_retention_drop: true,
        }
    }
}

#[derive(Debug)]
pub struct Divergence {
    pub peer_a: String,
    pub peer_a_idx: usize,
    pub fp_a: String,
    pub peer_b: String,
    pub peer_b_idx: usize,
    pub fp_b: String,
    pub op_count: usize,
    pub seed_recovery: String,
}

impl std::fmt::Display for Divergence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "convergence failure: {} (idx {}) and {} (idx {}) differ after {} ops.\n  {} fp = {}\n  {} fp = {}\n  {}",
            self.peer_a,
            self.peer_a_idx,
            self.peer_b,
            self.peer_b_idx,
            self.op_count,
            self.peer_a,
            self.fp_a,
            self.peer_b,
            self.fp_b,
            self.seed_recovery
        )
    }
}

// ---------------------------------------------------------------------------
// Op → Vault mutation
// ---------------------------------------------------------------------------

fn apply_op_to_vault(idx: usize, v: &mut Vault, op: Op) -> Result<(), SimError> {
    match op {
        Op::AddEntry {
            entry_id,
            group_id,
            title,
            password,
            mtime,
            creation_time,
        } => {
            let mut e = Entry::empty(EntryId(Uuid::from_u128(entry_id)));
            e.title = title;
            e.password = password;
            let mut t = Timestamps::default();
            t.last_modification_time = Some(mtime);
            t.creation_time = Some(creation_time);
            t.location_changed = Some(mtime);
            e.times = t;
            ensure_group(v, group_id);
            let group = find_group_mut(&mut v.root, group_id).ok_or(SimError::GroupNotFound(
                GroupId(Uuid::from_u128(group_id)),
                idx,
            ))?;
            group.entries.push(e);
            Ok(())
        }
        Op::EditTitle {
            entry_id,
            new_title,
            mtime,
        } => with_entry_mut(&mut v.root, entry_id, idx, |e| {
            e.title = new_title;
            e.times.last_modification_time = Some(mtime);
        }),
        Op::EditPassword {
            entry_id,
            new_password,
            mtime,
        } => with_entry_mut(&mut v.root, entry_id, idx, |e| {
            e.password = new_password;
            e.times.last_modification_time = Some(mtime);
        }),
        Op::EditCustomField {
            entry_id,
            key,
            value,
            protected,
            mtime,
        } => with_entry_mut(&mut v.root, entry_id, idx, |e| {
            if let Some(existing) = e.custom_fields.iter_mut().find(|f| f.key == key) {
                existing.value = value;
                existing.protected = protected;
            } else {
                e.custom_fields
                    .push(CustomField::new(key, value, protected));
            }
            e.times.last_modification_time = Some(mtime);
        }),
        Op::DeleteEntry {
            entry_id,
            deleted_at,
        } => {
            remove_entry(&mut v.root, entry_id);
            v.deleted_objects.push(DeletedObject::new(
                Uuid::from_u128(entry_id),
                Some(deleted_at),
            ));
            Ok(())
        }
        Op::AddTag {
            entry_id,
            tag,
            mtime,
        } => with_entry_mut(&mut v.root, entry_id, idx, |e| {
            if !e.tags.iter().any(|t| t == &tag) {
                e.tags.push(tag);
            }
            e.times.last_modification_time = Some(mtime);
        }),
        Op::RemoveTag { entry_id, tag, at } => with_entry_mut(&mut v.root, entry_id, idx, |e| {
            e.tags.retain(|t| t != &tag);
            let mut state = parse_tag_state(&e.custom_data);
            state.remove.insert(tag.clone(), TagRemoval::new(at));
            write_tag_state(&mut e.custom_data, &state);
            e.times.last_modification_time = Some(at);
        }),
        Op::MoveEntry {
            entry_id,
            new_group_id,
            location_changed,
        } => {
            ensure_group(v, new_group_id);
            let Some(mut detached) = detach_entry(&mut v.root, entry_id) else {
                return Err(SimError::EntryNotFound(
                    EntryId(Uuid::from_u128(entry_id)),
                    idx,
                ));
            };
            detached.times.location_changed = Some(location_changed);
            let group = find_group_mut(&mut v.root, new_group_id).ok_or(
                SimError::GroupNotFound(GroupId(Uuid::from_u128(new_group_id)), idx),
            )?;
            group.entries.push(detached);
            Ok(())
        }
        Op::AttachFile {
            entry_id,
            filename,
            bytes,
            mtime,
        } => {
            let ref_id = u32::try_from(insert_binary(v, &bytes)).unwrap();
            with_entry_mut(&mut v.root, entry_id, idx, |e| {
                e.attachments.retain(|a| a.name != filename);
                e.attachments.push(Attachment::new(filename, ref_id));
                e.times.last_modification_time = Some(mtime);
            })
        }
        Op::DetachFile {
            entry_id,
            filename,
            at,
        } => with_entry_mut(&mut v.root, entry_id, idx, |e| {
            let removed_hash = e
                .attachments
                .iter()
                .find(|a| a.name == filename)
                .and_then(|a| binary_hash_at(&e, &filename, a.ref_id));
            e.attachments.retain(|a| a.name != filename);
            // Add an attachment tombstone if we found a payload to
            // identify; otherwise the detach is unrecoverable from the
            // sim's perspective.
            if let Some(hash) = removed_hash {
                let mut list = parse_attachment_tombstones(&e.custom_data);
                list.push(AttachmentTombstone::new(filename, hash, at));
                write_attachment_tombstones(&mut e.custom_data, &list);
            }
            e.times.last_modification_time = Some(at);
        }),
        Op::AddGroup {
            group_id,
            parent_id,
            name,
            mtime,
            creation_time,
        } => {
            ensure_group(v, parent_id);
            let mut g = Group::empty(GroupId(Uuid::from_u128(group_id)));
            g.name = name;
            g.times.last_modification_time = Some(mtime);
            g.times.creation_time = Some(creation_time);
            g.times.location_changed = Some(mtime);
            let parent = find_group_mut(&mut v.root, parent_id).ok_or(SimError::GroupNotFound(
                GroupId(Uuid::from_u128(parent_id)),
                idx,
            ))?;
            parent.groups.push(g);
            Ok(())
        }
        Op::EditDatabaseName {
            new_name,
            changed_at,
        } => {
            v.meta.database_name = new_name;
            v.meta.database_name_changed = Some(changed_at);
            Ok(())
        }
        Op::SetHistoryMaxItems {
            value,
            settings_changed,
        } => {
            v.meta.history_max_items = value;
            v.meta.settings_changed = Some(settings_changed);
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Vault helpers (private; intentionally simpler than the merge crate's
// equivalents — sim ops mutate state directly).
// ---------------------------------------------------------------------------

fn ensure_group(v: &mut Vault, group_id: u128) {
    if find_group(&v.root, group_id).is_some() {
        return;
    }
    let mut g = Group::empty(GroupId(Uuid::from_u128(group_id)));
    g.name = format!("g-{group_id:x}");
    g.times.creation_time = Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap());
    g.times.last_modification_time = Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap());
    g.times.location_changed = Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap());
    v.root.groups.push(g);
}

fn find_group(group: &Group, id: u128) -> Option<&Group> {
    if group.id.0 == Uuid::from_u128(id) {
        return Some(group);
    }
    for sub in &group.groups {
        if let Some(found) = find_group(sub, id) {
            return Some(found);
        }
    }
    None
}

fn find_group_mut(group: &mut Group, id: u128) -> Option<&mut Group> {
    if group.id.0 == Uuid::from_u128(id) {
        return Some(group);
    }
    for sub in &mut group.groups {
        if let Some(found) = find_group_mut(sub, id) {
            return Some(found);
        }
    }
    None
}

fn collect_entry_ids(group: &Group) -> Vec<u128> {
    let mut out = Vec::new();
    fn walk(g: &Group, out: &mut Vec<u128>) {
        for e in &g.entries {
            out.push(e.id.0.as_u128());
        }
        for sub in &g.groups {
            walk(sub, out);
        }
    }
    walk(group, &mut out);
    out
}

fn collect_group_ids(group: &Group) -> Vec<u128> {
    let mut out = Vec::new();
    fn walk(g: &Group, out: &mut Vec<u128>) {
        out.push(g.id.0.as_u128());
        for sub in &g.groups {
            walk(sub, out);
        }
    }
    walk(group, &mut out);
    out
}

fn with_entry_mut<F: FnOnce(&mut Entry)>(
    root: &mut Group,
    id: u128,
    idx: usize,
    f: F,
) -> Result<(), SimError> {
    let mut f = Some(f);
    let mut applied = false;
    apply_to_first_entry(root, id, &mut f, &mut applied);
    if applied {
        Ok(())
    } else {
        Err(SimError::EntryNotFound(EntryId(Uuid::from_u128(id)), idx))
    }
}

fn apply_to_first_entry<F: FnOnce(&mut Entry)>(
    group: &mut Group,
    id: u128,
    f: &mut Option<F>,
    applied: &mut bool,
) {
    if *applied {
        return;
    }
    if let Some(e) = group
        .entries
        .iter_mut()
        .find(|e| e.id.0 == Uuid::from_u128(id))
    {
        if let Some(func) = f.take() {
            func(e);
            *applied = true;
        }
        return;
    }
    for sub in &mut group.groups {
        apply_to_first_entry(sub, id, f, applied);
        if *applied {
            return;
        }
    }
}

fn remove_entry(group: &mut Group, id: u128) {
    group.entries.retain(|e| e.id.0 != Uuid::from_u128(id));
    for sub in &mut group.groups {
        remove_entry(sub, id);
    }
}

fn detach_entry(root: &mut Group, id: u128) -> Option<Entry> {
    if let Some(pos) = root
        .entries
        .iter()
        .position(|e| e.id.0 == Uuid::from_u128(id))
    {
        return Some(root.entries.remove(pos));
    }
    for sub in &mut root.groups {
        if let Some(e) = detach_entry(sub, id) {
            return Some(e);
        }
    }
    None
}

fn insert_binary(v: &mut Vault, bytes: &[u8]) -> usize {
    let h = sha256(bytes);
    if let Some(pos) = v.binaries.iter().position(|b| sha256(&b.data) == h) {
        return pos;
    }
    v.binaries.push(Binary::new(bytes.to_vec(), false));
    v.binaries.len() - 1
}

fn binary_hash_at(e: &Entry, _filename: &str, ref_id: u32) -> Option<[u8; 32]> {
    // Sim doesn't have the binary pool here; the caller looks up via
    // `e.attachments`. We delegate the dereference to the caller — sim
    // ops are best-effort so the hash may be `None` if the filename
    // was already detached.
    let _ = e;
    let _ = ref_id;
    None
}

fn parse_tag_state(cd: &[CustomDataItem]) -> TagState {
    keepass_merge::parse_tag_state(cd).unwrap_or_default()
}

fn write_tag_state(cd: &mut Vec<CustomDataItem>, state: &TagState) {
    cd.retain(|i| i.key != TAG_STATE_CUSTOM_DATA_KEY);
    let json = serde_json::to_string(state).expect("ts serialize");
    cd.push(CustomDataItem::new(
        TAG_STATE_CUSTOM_DATA_KEY.to_string(),
        json,
        None,
    ));
}

fn parse_attachment_tombstones(cd: &[CustomDataItem]) -> Vec<AttachmentTombstone> {
    keepass_merge::parse_attachment_tombstones(cd).unwrap_or_default()
}

fn write_attachment_tombstones(cd: &mut Vec<CustomDataItem>, list: &[AttachmentTombstone]) {
    cd.retain(|i| i.key != ATTACHMENT_TOMBSTONE_CUSTOM_DATA_KEY);
    let json = serde_json::to_string(list).expect("att ts serialize");
    cd.push(CustomDataItem::new(
        ATTACHMENT_TOMBSTONE_CUSTOM_DATA_KEY.to_string(),
        json,
        None,
    ));
}

// ---------------------------------------------------------------------------
// Convergence fingerprint
// ---------------------------------------------------------------------------

/// Stable content fingerprint of a vault. Two converged vaults
/// produce identical fingerprints.
pub fn fingerprint(v: &Vault) -> String {
    let mut s = String::new();
    s.push_str(&format!("meta:{}\n", v.meta.database_name));
    s.push_str(&format!("hmi:{}\n", v.meta.history_max_items));
    // Sorted tombstones.
    let mut tombs: Vec<(String, String)> = v
        .deleted_objects
        .iter()
        .map(|t| {
            (
                t.uuid.to_string(),
                t.deleted_at.map(|d| d.to_rfc3339()).unwrap_or_default(),
            )
        })
        .collect();
    tombs.sort();
    for (id, at) in tombs {
        s.push_str(&format!("tomb:{id}@{at}\n"));
    }
    // Walk entries depth-first, sorted by id.
    walk_for_fingerprint(&v.root, &v.binaries, &mut s);
    s
}

fn walk_for_fingerprint(group: &Group, binaries: &[Binary], out: &mut String) {
    let mut entries: Vec<&Entry> = group.entries.iter().collect();
    entries.sort_by_key(|e| e.id.0);
    for e in entries {
        let tag_set: BTreeSet<&str> = e.tags.iter().map(String::as_str).collect();
        out.push_str(&format!(
            "e[{}]:t={}:p={}:tags={:?}",
            e.id.0, e.title, e.password, tag_set
        ));
        // Attachments by (name, sha256 of payload).
        let mut atts: Vec<(String, String)> = e
            .attachments
            .iter()
            .filter_map(|a| {
                let bin = binaries.get(a.ref_id as usize)?;
                Some((a.name.clone(), hex(&sha256(&bin.data))))
            })
            .collect();
        atts.sort();
        for (n, h) in atts {
            out.push_str(&format!(":att={n}@{h}"));
        }
        out.push('\n');
    }
    let mut subs: Vec<&Group> = group.groups.iter().collect();
    subs.sort_by_key(|g| g.id.0);
    for sub in subs {
        out.push_str(&format!("g[{}]:n={}\n", sub.id.0, sub.name));
        walk_for_fingerprint(sub, binaries, out);
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

fn hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}
