# MUTATION.md — the mutation API for `keepass-core`

Read this before touching anything that edits a `Vault`. This is the
design contract: every mutation PR must uphold the invariants here, in
the API shape here.

> **Phase 1 closed 2026-04-25.** The original 9-slice rollout plan
> shipped in PRs #74–#80 and has been archived to
> [`_project-management/complete/keepass-core/MUTATION-slicing-history.md`](../../_project-management/complete/keepass-core/MUTATION-slicing-history.md).
> The contract sections below (invariants, clock injection, history
> policy, ownership model, error enum, API sketch) remain
> load-bearing reference for any new mutation code.

## Goals

1. **Impossible to violate bookkeeping invariants by accident.** The
   caller cannot forget a timestamp or a history snapshot, because the
   library owns those writes.
2. **Secrets never leak through `String`.** Passwords and protected
   custom-field values cross the API boundary as `SecretString`.
3. **Deterministic under test.** Every timestamp and UUID generated
   during a mutation routes through injected sources that a test can
   pin.
4. **Ergonomic for Keys.** The call site for a routine edit is one or
   two lines. If you find yourself reaching through public fields, the
   shape is wrong.

## Bookkeeping invariants

Every mutation must maintain these automatically. Any PR that lets a
caller skip one is a bug, even if all the tests pass.

| Operation | Side effects the library applies |
|---|---|
| `add_entry` | Generate (or validate caller-supplied) UUID; stamp all `entry.times.*` to `clock.now()`; `previous_parent_group = None`; append to parent's `entries` |
| `edit_entry` (field change) | Per `HistoryPolicy`: optionally snapshot pre-edit entry into `entry.history`, truncate per `Meta::history_max_items` / `max_size`; stamp `entry.times.last_modification_time = clock.now()` once after the closure runs |
| `move_entry` | Stamp `entry.times.location_changed = clock.now()`; set `entry.previous_parent_group = Some(old_parent)`; splice out of old parent, push onto new parent; **no** history snapshot (move is not a field edit) |
| `delete_entry` | Append `DeletedObject { uuid, deleted_at: clock.now() }` to `vault.deleted_objects`; remove from tree |
| `touch_entry` | Stamp `entry.times.last_access_time = clock.now()`; **no** history snapshot, **no** `last_modification_time` stamp, **no** `meta.settings_changed` stamp, **no** binary-pool GC (leaf read-touch, not a content edit) |
| `add_group` | Same shape as `add_entry` (UUID, times, previous_parent_group = None) |
| `edit_group` | Stamp `group.times.last_modification_time = clock.now()`; **no** history (groups don't carry history) |
| `move_group` | Stamp `group.times.location_changed`; set `group.previous_parent_group`; reject if `new_parent` is a descendant of `id` (cycle) |
| `delete_group` | Recursively tombstone every entry and subgroup under it, each with its own `DeletedObject` record; then tombstone the group itself |
| Any Meta setter | Stamp `meta.settings_changed = clock.now()` |
| `add_custom_icon(data)` | SHA-256 dedup check; on fresh insert push to `meta.custom_icons` + stamp `meta.settings_changed`; on dedup hit no-op, no stamp. Pool GC runs only on `save_to_bytes` |
| `remove_custom_icon(id)` | Remove from `meta.custom_icons` if present + stamp `meta.settings_changed`; returns `false` with no stamp if absent. Does **not** unset dangling `entry.custom_icon_uuid` / `group.custom_icon_uuid` refs — `save_to_bytes`'s GC resolves those to `None` |
| `export_entry(id)` | Read-only; no timestamps stamped, no pool mutation, no `Meta` change. Returns `EntryNotFound` if `id` is absent |
| `import_entry(parent, entry, mint_new_uuid)` | Same shape as `add_entry` for the imported live entry (stamp all `times.*` to `clock.now()`, `previous_parent_group = None`, `usage_count = 0`); history-snapshot timestamps preserved verbatim; binaries content-hash-deduped against the destination pool; custom icons UUID-deduped (`mint_new_uuid=false`) or content-hash-deduped via `add_custom_icon` (`mint_new_uuid=true`); `DuplicateUuid` check covers the entry AND every history-snapshot UUID when `mint_new_uuid=false` |
| `recycle_entry(id)` | If `meta.recycle_bin_enabled = false` AND no bin exists, equivalent to `delete_entry`. Otherwise resolve/create the bin (fresh group + `meta.recycle_bin_uuid` + `meta.recycle_bin_changed` + `meta.settings_changed` on first use) and `move_entry` into it (`times.location_changed`, `previous_parent_group`). Returns `Some(bin_id)` on move; `None` on already-inside-bin or on hard-delete fallback. No `DeletedObject` on move |
| `recycle_group(id)` | Same shape as `recycle_entry`, for groups. `CannotDeleteRoot` if `id` is the root; `CircularMove` if `id` is the bin itself |
| `empty_recycle_bin()` | For each direct child of the bin: equivalent to `delete_entry` / `delete_group` (recursive tombstoning via `DeletedObject`). No `Meta` stamp. Returns the count of direct children removed; `Ok(0)` if no bin exists |
| `rekey` | Refresh `MasterSeed`, `EncryptionIv`, KDF seed/salt; stamp `meta.master_key_changed = clock.now()`; **does not** touch entries |

## Clock injection

The library is the source of truth for `now()`. Callers never pass a
timestamp into a mutation method.

```rust
pub trait Clock {
    fn now(&self) -> DateTime<Utc>;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> { Utc::now() }
}

// Test helpers live behind #[cfg(test)] or a `testing` feature:
pub struct FixedClock(pub DateTime<Utc>);
impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> { self.0 }
}
```

`Kdbx<Unlocked>` stores a `Box<dyn Clock>`. Default is `SystemClock`;
tests swap in `FixedClock` or a monotonic counter. The clock is set at
unlock time and is not swappable afterwards — a mid-session clock
change would let timestamps travel backwards through the same
vault, which breaks history ordering.

```rust
impl Kdbx<HeaderRead> {
    pub fn unlock(self, key: &CompositeKey) -> Result<Kdbx<Unlocked>, Error>;
    pub fn unlock_with_clock(
        self,
        key: &CompositeKey,
        clock: Box<dyn Clock>,
    ) -> Result<Kdbx<Unlocked>, Error>;
}
```

## History policy

History snapshots are caller-controlled per edit. The library does
not impose a "always snapshot" or "never snapshot" rule — different
hosts want different behaviour, and coalescing rapid saves is a
legitimate policy.

```rust
#[non_exhaustive]
pub enum HistoryPolicy {
    /// Snapshot the pre-edit entry into `entry.history` before
    /// applying the closure. The canonical KeePass behaviour.
    Snapshot,

    /// Skip the snapshot. Use for fixup edits the caller considers
    /// cosmetic (correcting a typo immediately after the original
    /// save, bulk-reencode after a model migration, etc.).
    NoSnapshot,

    /// Snapshot only if the most recent history entry is older than
    /// `since`. Implements "coalesce edits within a window" — e.g.
    /// `Duration::hours(24)` means at most one snapshot per day.
    /// If there is no prior history, always snapshots.
    SnapshotIfOlderThan(chrono::Duration),
}
```

Truncation after snapshot follows `Meta::history_max_items` and
`Meta::history_max_size`; oldest entries go first.

The policy is a parameter on every mutation, not state on the Kdbx.
Reason: callers that want a default wrap the library with their own
helper; the library stays policy-free.

## Ownership model

Hybrid:

- **Tree-level operations (add / delete / move)** are direct methods
  on `Kdbx<Unlocked>`. Each call is one atomic operation with its
  own bookkeeping. Returns `Result` because they can fail
  (not-found, circular move, duplicate UUID).

- **Field-level operations (set title, set password, etc.)** run
  inside a scoped closure passed to `edit_entry` / `edit_group`. The
  library:
  1. Locates the target, returns an `EntryEditor<'_>` / `GroupEditor<'_>`.
  2. Invokes the closure.
  3. After the closure returns, runs the bookkeeping exactly once
     (history snapshot per policy, timestamp stamp).

  This model makes "I edited three fields; one snapshot, one
  timestamp" the natural outcome. Per-field setters would fire
  three snapshots and three timestamps, which is wrong.

The closure returns the caller's choice of `R`, wrapped in `Result`
by the outer method. The editor itself is `#[non_exhaustive]` and
only exposes the intended mutation surface — no access to `history`,
`times`, `previous_parent_group`, or any other field the library
owns.

## First-cut API sketch

```rust
// ------ Kdbx<Unlocked> surface ------

impl Kdbx<Unlocked> {
    pub fn vault(&self) -> &Vault;

    // Tree-level: one operation, own bookkeeping.
    pub fn add_entry(
        &mut self,
        parent: GroupId,
        template: NewEntry,
    ) -> Result<EntryId, ModelError>;

    pub fn move_entry(
        &mut self,
        id: EntryId,
        new_parent: GroupId,
    ) -> Result<(), ModelError>;

    pub fn delete_entry(&mut self, id: EntryId) -> Result<(), ModelError>;

    // Field-level: closure scope = commit point.
    pub fn edit_entry<R>(
        &mut self,
        id: EntryId,
        policy: HistoryPolicy,
        f: impl FnOnce(&mut EntryEditor<'_>) -> R,
    ) -> Result<R, ModelError>;

    // Groups mirror entries; groups have no history policy parameter.
    pub fn add_group(
        &mut self,
        parent: GroupId,
        template: NewGroup,
    ) -> Result<GroupId, ModelError>;

    pub fn move_group(
        &mut self,
        id: GroupId,
        new_parent: GroupId,
    ) -> Result<(), ModelError>;

    pub fn delete_group(&mut self, id: GroupId) -> Result<(), ModelError>;

    pub fn edit_group<R>(
        &mut self,
        id: GroupId,
        f: impl FnOnce(&mut GroupEditor<'_>) -> R,
    ) -> Result<R, ModelError>;

    // Meta — no closure; the full Meta surface is small enough.
    pub fn set_database_name(&mut self, name: impl Into<String>);
    pub fn set_database_description(&mut self, d: impl Into<String>);
    pub fn set_default_username(&mut self, u: impl Into<String>);
    pub fn set_color(&mut self, hex: impl Into<String>);
    pub fn set_recycle_bin(
        &mut self,
        enabled: bool,
        group: Option<GroupId>,
    );
    // ... etc, each stamps Meta::settings_changed ...

    pub fn rekey(&mut self, new_key: &CompositeKey) -> Result<(), CryptoError>;
}

// ------ EntryEditor ------

impl EntryEditor<'_> {
    pub fn set_title(&mut self, title: impl Into<String>);
    pub fn set_username(&mut self, u: impl Into<String>);
    pub fn set_password(&mut self, pw: SecretString);
    pub fn set_url(&mut self, url: impl Into<String>);
    pub fn set_notes(&mut self, notes: impl Into<String>);

    pub fn set_tags(&mut self, tags: Vec<String>);
    pub fn add_tag(&mut self, tag: impl Into<String>);
    pub fn remove_tag(&mut self, tag: &str);

    pub fn set_custom_field(
        &mut self,
        key: impl Into<String>,
        value: CustomFieldValue,   // wraps SecretString for protected, String for plain
    );
    pub fn remove_custom_field(&mut self, key: &str) -> bool;

    pub fn set_override_url(&mut self, url: impl Into<String>);
    pub fn set_foreground_color(&mut self, hex: impl Into<String>);
    pub fn set_background_color(&mut self, hex: impl Into<String>);
    pub fn set_custom_icon(&mut self, icon: Option<Uuid>);
    pub fn set_quality_check(&mut self, enabled: bool);

    pub fn set_expiry(&mut self, at: Option<DateTime<Utc>>);
    pub fn set_auto_type(&mut self, auto_type: AutoType);

    // Attachments resolve through the Vault::binaries pool automatically.
    pub fn attach(
        &mut self,
        name: impl Into<String>,
        data: Vec<u8>,
        protected: bool,
    );
    pub fn detach(&mut self, name: &str) -> bool;
}

// ------ GroupEditor ------  (similar; no history)

// ------ Builders ------

pub struct NewEntry { /* ... */ }
impl NewEntry {
    pub fn new(title: impl Into<String>) -> Self;   // minimum
    pub fn username(self, u: impl Into<String>) -> Self;
    pub fn password(self, pw: SecretString) -> Self;
    pub fn url(self, url: impl Into<String>) -> Self;
    pub fn notes(self, n: impl Into<String>) -> Self;
    pub fn tags(self, tags: Vec<String>) -> Self;
    // Caller can pre-set a UUID for import scenarios:
    pub fn with_uuid(self, uuid: Uuid) -> Self;
}

pub struct NewGroup { /* ... */ }
// similar

// ------ Errors ------

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ModelError {
    #[error("entry {0:?} not found")]
    EntryNotFound(EntryId),
    #[error("group {0:?} not found")]
    GroupNotFound(GroupId),
    #[error("move would create a cycle: group {moving:?} cannot become a descendant of itself via {new_parent:?}")]
    CircularMove { moving: GroupId, new_parent: GroupId },
    #[error("UUID {0} already in use in this vault")]
    DuplicateUuid(Uuid),
    #[error("cannot delete the root group")]
    CannotDeleteRoot,
}
```

Top-level `Error` gains `Model(#[from] ModelError)`.

## Secret hygiene at the boundary

`SecretString` comes from the `secrecy` crate (already a dep). It:

- Wraps a `Zeroize`d inner `String`.
- Refuses `Debug` / `Display` — prints `[REDACTED]`.
- Exposes bytes only via `ExposeSecret::expose_secret(&self)`, which
  is intentionally ugly to make audit grep for.

Protected custom-field values take `SecretString` too, via
`CustomFieldValue`:

```rust
pub enum CustomFieldValue {
    Plain(String),
    Protected(SecretString),
}
```

`EntryEditor::set_custom_field` routes appropriately, stamping
`CustomField::protected` accordingly.

## What's explicitly out of scope for v1

- Undo / redo. Adding it later is a matter of capturing
  `Mutation` records from inside the library; doesn't need a change
  to this API.
- Batch / transaction across multiple entries. If Keys needs "edit
  five entries atomically", we can add `Kdbx::transaction(|tx| { ... })`
  later; for now, each mutation is its own atom.
- Schema migration (KDBX3 → KDBX4 on save). Lives elsewhere.
- Write-path concurrency. `&mut self` is the sync boundary; if
  multi-threaded access is ever needed, that's an outer wrapper.

## Story-test (the shape check)

If you can write this, the API is right:

```rust
let mut kdbx = Kdbx::<Sealed>::open(path)?
    .read_header()?
    .unlock(&composite_key)?;

// Add a new entry under the root group.
let id = kdbx.add_entry(
    kdbx.vault().root.id,
    NewEntry::new("Gmail")
        .username("alice@example.com")
        .password(SecretString::new("hunter2".into()))
        .url("https://mail.google.com"),
)?;

// Later — user edits the password.
kdbx.edit_entry(id, HistoryPolicy::SnapshotIfOlderThan(Duration::days(1)), |e| {
    e.set_password(SecretString::new("hunter3".into()));
})?;

// User deletes the entry.
kdbx.delete_entry(id)?;

// Save.
std::fs::write(path, kdbx.save_to_bytes()?)?;
```

No `.unwrap()` on `find`, no direct field writes, no forgotten
timestamps. That's the shape.
