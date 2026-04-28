//! The [`Kdbx`] typestate machine.
//!
//! A KDBX file passes through four distinct states on the way from bytes on
//! disk to a usable vault, and through three states on the way back out:
//!
//! ```text
//!  ┌────────┐  read_header   ┌────────────┐  unlock   ┌──────────┐  write
//!  │ Sealed │ ──────────────▶│ HeaderRead │ ─────────▶│ Unlocked │ ─────▶ bytes
//!  └────────┘                └────────────┘           └──────────┘
//! ```
//!
//! Each state is a distinct Rust type. Methods that only make sense in a
//! particular state exist only on the impl block for that state. The compiler
//! therefore statically prevents misuse: `vault.entries()` on a sealed vault
//! is a compile error, not a runtime one.
//!
//! ## Why each state exists
//!
//! - [`Sealed`] — the file bytes have been read into memory and the signature
//!   block has been validated. The outer header is still unparsed.
//! - [`HeaderRead`] — the outer header has been parsed; we know the KDBX
//!   version, cipher, KDF parameters, and seeds. The master key has **not**
//!   yet been applied. The only legal operation is `unlock`.
//! - [`Unlocked`] — the master key has been derived, block HMACs verified
//!   (on KDBX4), payload decrypted, decompressed, and the inner XML parsed
//!   into the [`crate::model::Vault`] tree. Read and write operations
//!   are both available — including [`Kdbx::<Unlocked>::save_to_bytes`].

use std::collections::{HashMap, HashSet};
use std::fs;
use std::marker::PhantomData;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::crypto::{
    CryptoError, InnerStreamCipher, aes_256_cbc_decrypt, aes_256_cbc_encrypt, chacha20_decrypt,
    chacha20_encrypt, compress, decompress, derive_cipher_key, derive_hmac_base_key,
    derive_transformed_key,
};
use crate::error::Error;
use crate::format::{
    EncryptionIv, FileSignature, FormatError, HASHED_BLOCK_DEFAULT_SIZE, HMAC_BLOCK_DEFAULT_SIZE,
    InnerBinary, InnerHeader, InnerStreamAlgorithm, KnownCipher, MasterSeed, OuterHeader,
    SIGNATURE_1, SIGNATURE_2, TransformSeed, VarDictionary, VarValue, Version, compute_header_hash,
    compute_header_hmac, read_hashed_block_stream, read_header_fields, read_hmac_block_stream,
    verify_header_hash, verify_header_hmac, write_hashed_block_stream, write_hmac_block_stream,
};
use crate::model::entry_editor::PendingBinaryOps;
use crate::model::{
    Attachment, AutoType, Binary, Clock, CustomIcon, DeletedObject, Entry, EntryEditor, EntryId,
    Group, GroupEditor, GroupId, HistoryPolicy, ModelError, NewEntry, NewGroup, PortableEntry,
    SystemClock, Timestamps, Vault,
};
use crate::secret::{CompositeKey, TransformedKey};
use crate::xml::{
    decode_vault_with_cipher, encode_vault_kdbx3_with_cipher_and_header_hash,
    encode_vault_with_cipher,
};

// ---------------------------------------------------------------------------
// State markers
// ---------------------------------------------------------------------------

/// State marker: the file bytes are present and the signature block has been
/// validated; the outer header has not yet been parsed.
#[derive(Debug)]
pub struct Sealed {
    _private: PhantomData<()>,
}

/// State marker: the outer header has been parsed; the payload is still
/// encrypted.
#[derive(Debug)]
pub struct HeaderRead {
    header: OuterHeader,
    /// Offset (in `Kdbx::bytes`) of the first byte past the end of the outer
    /// header. For KDBX3 this is the start of the encrypted payload; for
    /// KDBX4 it is the start of the 32-byte header SHA-256, followed by the
    /// 32-byte header HMAC, followed by the HMAC-block stream.
    header_end: usize,
}

/// State marker: the vault has been fully decrypted, parsed, and is ready
/// for read-only access or write-back via [`Kdbx::<Unlocked>::save_to_bytes`].
///
/// The framing bits (outer header, inner header, and the composite key
/// that unlocked the file) are retained so a save can reuse them without
/// re-running the (expensive) KDF.
#[derive(Debug)]
pub struct Unlocked {
    vault: Vault,
    /// The clock used to stamp timestamps during mutations. Set at
    /// unlock time via [`Kdbx::<HeaderRead>::unlock`] (`SystemClock`)
    /// or [`Kdbx::<HeaderRead>::unlock_with_clock`] (caller-supplied).
    /// Not swappable after unlock — mid-session clock changes would
    /// let timestamps travel backwards, which breaks history ordering.
    clock: Box<dyn Clock>,
    /// Outer header as parsed at unlock time. `save_to_bytes` reuses
    /// every field — same cipher, same master seed, same KDF params —
    /// so `unlock → save → re-open → unlock` produces the same vault
    /// without touching the KDF.
    outer_header: OuterHeader,
    /// The inner-stream cipher's algorithm and key, retained so
    /// `save_to_bytes` can spin up a fresh [`InnerStreamCipher`] that
    /// encrypts protected values symmetrically with how they were
    /// decrypted on unlock. Sourced from the inner header on KDBX4 and
    /// from the outer header's `InnerRandomStream*` TLVs on KDBX3.
    inner_stream: Option<InnerStreamParams>,
    /// The transformed (post-KDF) key derived at unlock time. Retained
    /// so that `save_to_bytes` can derive the cipher key and HMAC base
    /// key directly, skipping the expensive Argon2 / AES-KDF round.
    transformed_key: TransformedKey,
}

/// Inner-stream cipher parameters retained across [`Kdbx::<Unlocked>`]
/// for symmetric re-encryption on [`save_to_bytes`](Kdbx::save_to_bytes).
#[derive(Debug, Clone)]
struct InnerStreamParams {
    algorithm: InnerStreamAlgorithm,
    key: Vec<u8>,
}

// ---------------------------------------------------------------------------
// The typestate container
// ---------------------------------------------------------------------------

/// A KeePass database in one of the lifecycle states [`Sealed`],
/// [`HeaderRead`], or [`Unlocked`].
///
/// Create a [`Kdbx<Sealed>`] from bytes via [`Kdbx::open_from_bytes`] or from
/// a path via [`Kdbx::open`]. Transition to [`Kdbx<HeaderRead>`] by calling
/// [`Kdbx::<Sealed>::read_header`], and to [`Kdbx<Unlocked>`] by supplying
/// a composite key to [`Kdbx::<HeaderRead>::unlock`].
#[derive(Debug)]
pub struct Kdbx<State> {
    /// The full file bytes. Held across state transitions so that later
    /// stages can slice the encrypted payload, HMAC blocks, etc.
    bytes: Vec<u8>,
    /// Parsed signature block (magic + major + minor).
    signature: FileSignature,
    /// Version derived from the signature's major number. Cached so that
    /// every state can expose it without re-parsing.
    version: Version,
    /// State-specific data. In `Sealed` this is a zero-sized marker; in
    /// `HeaderRead` it carries the parsed header.
    state: State,
}

// ---------------------------------------------------------------------------
// Methods available in every state
// ---------------------------------------------------------------------------

impl<S> Kdbx<S> {
    /// The validated signature block from the first 12 bytes.
    #[must_use]
    pub fn signature(&self) -> FileSignature {
        self.signature
    }

    /// The KDBX major version (`V3` or `V4`).
    #[must_use]
    pub fn version(&self) -> Version {
        self.version
    }
}

// ---------------------------------------------------------------------------
// Sealed: open and read_header
// ---------------------------------------------------------------------------

impl Kdbx<Sealed> {
    /// Open a KDBX database from its raw bytes.
    ///
    /// Validates the 12-byte signature block and classifies the version. No
    /// further parsing — the outer header stays sealed until
    /// [`Self::read_header`] is called.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Format`] if the magic bytes are wrong, the file is
    /// shorter than 12 bytes, or the major version is not 3 or 4.
    pub fn open_from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        let signature = FileSignature::read(&bytes)?;
        let version = signature.version()?;
        Ok(Self {
            bytes,
            signature,
            version,
            state: Sealed {
                _private: PhantomData,
            },
        })
    }

    /// Convenience: read a path into memory and pass it to
    /// [`Self::open_from_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the file can't be read, or the underlying
    /// format errors from [`Self::open_from_bytes`].
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let bytes = fs::read(path)?;
        Self::open_from_bytes(bytes)
    }

    /// Parse the outer header, transitioning to [`Kdbx<HeaderRead>`].
    ///
    /// After this call the outer header is available via
    /// [`Kdbx::<HeaderRead>::header`]. Seeds, cipher IDs, and (for KDBX4) the
    /// VarDictionary-encoded KDF parameters are all decoded; key derivation
    /// has not happened yet.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Format`] if any TLV record is malformed, any
    /// mandatory field is missing, or an unknown cipher / compression ID is
    /// encountered.
    pub fn read_header(self) -> Result<Kdbx<HeaderRead>, Error> {
        let mut cursor = &self.bytes[FileSignature::LEN..];
        let before = cursor.len();
        let (fields, _end) = read_header_fields(&mut cursor, self.version.header_length_width())?;
        let header = OuterHeader::parse(&fields, self.version).map_err(FormatError::from)?;
        // `cursor` has been advanced past the end-of-header sentinel.
        let header_end = FileSignature::LEN + (before - cursor.len());

        Ok(Kdbx {
            bytes: self.bytes,
            signature: self.signature,
            version: self.version,
            state: HeaderRead { header, header_end },
        })
    }
}

// ---------------------------------------------------------------------------
// HeaderRead: accessors and unlock
// ---------------------------------------------------------------------------

impl Kdbx<HeaderRead> {
    /// The parsed outer header.
    #[must_use]
    pub fn header(&self) -> &OuterHeader {
        &self.state.header
    }

    /// Byte slice of everything after the outer header — i.e. the encrypted
    /// payload on KDBX3, or the header-HMAC + HMAC-block stream on KDBX4.
    ///
    /// Exposed for testing and for downstream unlock wiring.
    #[must_use]
    pub fn payload_bytes(&self) -> &[u8] {
        &self.bytes[self.state.header_end..]
    }

    /// Byte slice of the outer header itself — signature + TLV records up to
    /// and including the end-of-header sentinel. Used by KDBX4 to compute
    /// the header SHA-256 and HMAC.
    #[must_use]
    pub fn header_bytes(&self) -> &[u8] {
        &self.bytes[..self.state.header_end]
    }

    /// Apply the composite key to unlock the vault.
    ///
    /// Runs the full KDBX decryption pipeline:
    ///
    /// 1. Derive the transformed key via the KDF (AES-KDF on KDBX3,
    ///    Argon2d/Argon2id on KDBX4).
    /// 2. Derive the cipher key (and, on KDBX4, the HMAC base key).
    /// 3. KDBX4 only: verify the header SHA-256 and HMAC-SHA-256 tags
    ///    against the caller's key.
    /// 4. Assemble the ciphertext — from the HMAC-block stream (KDBX4)
    ///    or directly from the raw payload (KDBX3).
    /// 5. Decrypt with the outer cipher (currently AES-256-CBC only;
    ///    ChaCha20 and Twofish-CBC land in follow-up PRs).
    /// 6. KDBX3: verify the 32-byte stream-start-bytes sentinel and
    ///    reassemble the hashed-block stream.
    /// 7. Decompress if the header declared gzip.
    /// 8. KDBX4: parse the inner header to pick up the inner-stream
    ///    cipher parameters.
    ///    KDBX3: read the inner-stream parameters from the outer header.
    /// 9. Decode the inner XML into a typed [`Vault`], decrypting
    ///    protected values against the inner-stream cipher in document
    ///    order.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] on any key-stage failure (wrong
    /// password, tampered payload, HMAC mismatch, bad padding, inner-
    /// stream cipher construction failure). Returns [`Error::Format`]
    /// on structural failures (malformed block stream, malformed inner
    /// header, unsupported cipher). Returns [`Error::Xml`] on
    /// malformed inner XML.
    ///
    /// The crypto vs format split follows the error-collapse discipline
    /// from §4.8.7 of the design doc: we deliberately do **not**
    /// distinguish "wrong key" from "corrupt ciphertext" — both surface
    /// as a generic decryption failure, so an attacker cannot learn
    /// anything about the key from the error variant alone.
    pub fn unlock(self, composite: &CompositeKey) -> Result<Kdbx<Unlocked>, Error> {
        self.unlock_with_clock(composite, Box::new(SystemClock))
    }

    /// Like [`Self::unlock`] but uses the caller-supplied [`Clock`]
    /// for any timestamps stamped during later mutations.
    ///
    /// Production callers should use [`Self::unlock`], which hands in
    /// a [`SystemClock`]. Tests use this entry point to pin the
    /// mutation clock to a deterministic value (e.g. a
    /// [`crate::model::FixedClock`]) so assertions on
    /// `entry.times.*` can be exact.
    ///
    /// The clock is stored on the resulting [`Kdbx<Unlocked>`] and is
    /// not swappable afterwards. A mid-session clock change would
    /// break history ordering invariants.
    ///
    /// # Errors
    ///
    /// Same as [`Self::unlock`].
    pub fn unlock_with_clock(
        self,
        composite: &CompositeKey,
        clock: Box<dyn Clock>,
    ) -> Result<Kdbx<Unlocked>, Error> {
        let mut state = do_unlock(&self.bytes, &self.state, composite)?;
        state.clock = clock;
        Ok(Kdbx {
            bytes: self.bytes,
            signature: self.signature,
            version: self.version,
            state,
        })
    }
}

// ---------------------------------------------------------------------------
// Unlocked: vault access
// ---------------------------------------------------------------------------

impl Kdbx<Unlocked> {
    /// The decoded vault.
    #[must_use]
    pub fn vault(&self) -> &Vault {
        &self.state.vault
    }

    /// The [`Clock`] this unlocked database uses to stamp timestamps
    /// during mutations. Either [`SystemClock`] (default, from
    /// [`Kdbx::<HeaderRead>::unlock`]) or whatever was passed to
    /// [`Kdbx::<HeaderRead>::unlock_with_clock`].
    #[must_use]
    pub fn clock(&self) -> &dyn Clock {
        &*self.state.clock
    }

    /// Replace the in-memory vault wholesale.
    ///
    /// Intended for bulk-mutation consumers that produce a fully-formed
    /// replacement [`Vault`] outside the editor methods — chiefly the
    /// `keepass-merge` crate's `apply_merge`, which mutates a `&mut Vault`
    /// it has been handed by the caller. Once the merge has run on a
    /// caller-owned clone, the caller swaps the merged vault back in via
    /// this method.
    ///
    /// **Invariants are the caller's responsibility.** The replacement
    /// must satisfy every invariant the editor methods (`add_entry`,
    /// `edit_entry`, `move_entry`, …) normally maintain: UUID uniqueness
    /// across entries and groups, well-formed parent-id chains, internally
    /// consistent `<DeletedObjects>` tombstones, custom-icon references
    /// pointing at icons in the pool, etc. Use this only when the
    /// replacement comes from a tool that asserts those invariants —
    /// e.g. `keepass-merge::apply_merge`. There is no validation pass.
    ///
    /// The crypto envelope (composite key, header KDF parameters,
    /// encryption IV) is **not** affected; only the decoded vault model
    /// is replaced. The next [`Self::save_to_bytes`] re-encrypts the new
    /// vault under the existing key.
    pub fn replace_vault(&mut self, vault: Vault) {
        self.state.vault = vault;
    }

    /// Insert a new [`Entry`] under the group identified by `parent`.
    ///
    /// The library owns UUID generation (unless the builder set one
    /// via [`NewEntry::with_uuid`]), fills in every
    /// [`Timestamps`] field from [`Self::clock`], sets
    /// `previous_parent_group = None`, and appends the entry to the
    /// parent's child list. Returns the new entry's [`EntryId`].
    ///
    /// # Errors
    ///
    /// - [`ModelError::GroupNotFound`] if `parent` is not in the vault.
    /// - [`ModelError::DuplicateUuid`] if the builder supplied a UUID
    ///   that is already in use anywhere in the vault.
    ///
    /// # Panics
    ///
    /// Does not panic under any input. The second `find_group_mut`
    /// call is `.expect()`ed because the first call has already
    /// proved the group exists.
    pub fn add_entry(
        &mut self,
        parent: GroupId,
        template: NewEntry,
    ) -> Result<EntryId, ModelError> {
        let uuid = match template.uuid {
            Some(u) => {
                if uuid_in_use(&self.state.vault, u) {
                    return Err(ModelError::DuplicateUuid(u));
                }
                u
            }
            None => fresh_uuid(&self.state.vault),
        };

        // Locate the target parent up front so we fail early.
        if find_group_mut(&mut self.state.vault.root, parent).is_none() {
            return Err(ModelError::GroupNotFound(parent));
        }

        let now = self.state.clock.now();
        let entry = Entry {
            id: EntryId(uuid),
            title: template.title,
            username: template.username,
            password: template.password,
            url: template.url,
            notes: template.notes,
            custom_fields: Vec::new(),
            tags: template.tags,
            history: Vec::new(),
            attachments: Vec::new(),
            foreground_color: String::new(),
            background_color: String::new(),
            override_url: String::new(),
            custom_icon_uuid: None,
            custom_data: Vec::new(),
            quality_check: true,
            previous_parent_group: None,
            auto_type: AutoType::default(),
            times: Timestamps {
                creation_time: Some(now),
                last_modification_time: Some(now),
                last_access_time: Some(now),
                location_changed: Some(now),
                expiry_time: None,
                expires: false,
                usage_count: 0,
            },
            icon_id: 0,
            unknown_xml: Vec::new(),
        };

        // Re-locate under &mut; infallible because we just checked.
        let target = find_group_mut(&mut self.state.vault.root, parent)
            .expect("group existence checked above");
        target.entries.push(entry);
        Ok(EntryId(uuid))
    }

    /// Remove the entry with the given id, recording a tombstone in
    /// `vault.deleted_objects`.
    ///
    /// The tombstone's `deleted_at` is stamped from [`Self::clock`].
    ///
    /// # Errors
    ///
    /// - [`ModelError::EntryNotFound`] if no entry with that id exists
    ///   anywhere in the vault.
    pub fn delete_entry(&mut self, id: EntryId) -> Result<(), ModelError> {
        let (removed, _old_parent) = remove_entry_with_parent(&mut self.state.vault.root, id)
            .ok_or(ModelError::EntryNotFound(id))?;
        let now = self.state.clock.now();
        self.state.vault.deleted_objects.push(DeletedObject {
            uuid: removed.id.0,
            deleted_at: Some(now),
        });
        Ok(())
    }

    /// Move an entry from its current parent to `new_parent`.
    ///
    /// Bookkeeping applied automatically:
    /// - `entry.times.location_changed = self.clock().now()`
    /// - `entry.previous_parent_group = Some(old_parent)`
    /// - No history snapshot — MUTATION.md §"Bookkeeping invariants"
    ///   explicitly excludes `move_entry` from history: a move is not
    ///   a field edit.
    ///
    /// A no-op move (same parent as current) still stamps
    /// `location_changed` and records `previous_parent_group = Some(same)`
    /// — the caller expressed intent, so we don't silently skip.
    ///
    /// # Errors
    ///
    /// - [`ModelError::EntryNotFound`] if `id` is not in the vault.
    /// - [`ModelError::GroupNotFound`] if `new_parent` is not in the
    ///   vault. The entry is *not* removed in this case — we check the
    ///   destination before touching the source.
    ///
    /// # Panics
    ///
    /// Does not panic under any input. The second `find_group_mut`
    /// call is `.expect()`ed because the first call has already
    /// proved the destination exists.
    pub fn move_entry(&mut self, id: EntryId, new_parent: GroupId) -> Result<(), ModelError> {
        // Check the destination first so a failure leaves the entry
        // where it was.
        if find_group_mut(&mut self.state.vault.root, new_parent).is_none() {
            return Err(ModelError::GroupNotFound(new_parent));
        }

        let (mut entry, old_parent) = remove_entry_with_parent(&mut self.state.vault.root, id)
            .ok_or(ModelError::EntryNotFound(id))?;

        entry.previous_parent_group = Some(old_parent);
        let now = self.state.clock.now();
        entry.times.location_changed = Some(now);

        let target = find_group_mut(&mut self.state.vault.root, new_parent)
            .expect("destination existence checked above");
        target.entries.push(entry);
        Ok(())
    }

    /// Field-level edit on a single entry, with one automatic
    /// history snapshot (per `policy`) and one automatic
    /// `last_modification_time` stamp after the closure returns.
    ///
    /// The closure is handed an [`EntryEditor`] that exposes only
    /// the legitimately caller-mutable fields. Setters on the editor
    /// (title / username / password / url / notes in this slice)
    /// touch the target entry in-place; the library owns the
    /// bookkeeping around them.
    ///
    /// History snapshot behaviour is determined by `policy`:
    /// - [`HistoryPolicy::Snapshot`]: always clone the pre-edit entry
    ///   into `entry.history` before the closure runs.
    /// - [`HistoryPolicy::NoSnapshot`]: skip the snapshot.
    /// - `HistoryPolicy::SnapshotIfOlderThan(since)`: snapshot
    ///   only if the most recent history entry's
    ///   `last_modification_time` is older than `clock.now() - since`,
    ///   or if history is empty.
    ///
    /// After a snapshot is taken the history list is truncated to
    /// [`crate::model::Meta::history_max_items`] entries (negative
    /// values mean unlimited). `history_max_size` is treated as an
    /// approximate soft budget on the serialised canonical-field
    /// byte count — entries are dropped from the front (oldest first)
    /// until the estimate fits.
    ///
    /// # Errors
    ///
    /// - [`ModelError::EntryNotFound`] if `id` is not in the vault.
    pub fn edit_entry<R>(
        &mut self,
        id: EntryId,
        policy: HistoryPolicy,
        f: impl FnOnce(&mut EntryEditor<'_>) -> R,
    ) -> Result<R, ModelError> {
        // Hoist everything we need off `self.state` before we take
        // a long-lived `&mut Entry` borrow — the borrow checker
        // otherwise forbids touching `self.state.clock` / meta
        // through the rest of the method.
        let now = self.state.clock.now();
        let history_max_items = self.state.vault.meta.history_max_items;
        let history_max_size = self.state.vault.meta.history_max_size;

        let entry =
            find_entry_mut(&mut self.state.vault.root, id).ok_or(ModelError::EntryNotFound(id))?;

        let should_snapshot = should_snapshot_now(policy, &entry.history, now);

        if should_snapshot {
            let mut snap = entry.clone();
            // KeePass history entries never nest their own history.
            snap.history.clear();
            entry.history.push(snap);
            truncate_history(&mut entry.history, history_max_items, history_max_size);
        }

        // Scope the editor borrow so `entry` is freely usable again
        // when we stamp the last-modification timestamp below. Pull
        // any staged attach intents out of the editor before its
        // borrow drops — they get applied against the Vault's
        // shared binaries pool after the &mut Entry borrow ends.
        let (result, pending) = {
            let mut editor = EntryEditor::new(entry);
            let r = f(&mut editor);
            let p = editor.take_pending_binary_ops();
            (r, p)
        };

        entry.times.last_modification_time = Some(now);
        // The &mut Entry borrow ends here; from this point on we
        // have &mut Vault available for pool-level work.
        let _ = entry;

        apply_pending_attaches(&mut self.state.vault, id, pending);
        gc_binaries_pool(&mut self.state.vault);

        Ok(result)
    }

    /// Stamp `entry.times.last_access_time = clock.now()` on the
    /// entry identified by `id`, without running any other
    /// bookkeeping.
    ///
    /// Counterpart for read-touch actions on the Keys-app side:
    /// AutoFill credential fulfilment from the extension, in-app
    /// password reveal, and anything else
    /// `DatabaseManager.recordAccess` classifies as significant.
    /// The library owns the stamp (FFI clock-ownership rule A);
    /// callers signal the intent, we write the value.
    ///
    /// Explicit non-effects (asserted by integration tests):
    ///
    /// - No history snapshot. A read-touch is not a content edit.
    /// - No [`crate::model::Meta::settings_changed`] stamp. A
    ///   per-entry access is not a settings change.
    /// - No [`crate::model::Timestamps::last_modification_time`]
    ///   update. The entry's content hasn't changed.
    /// - No [`crate::model::Timestamps::location_changed`] update.
    ///   The entry hasn't moved.
    /// - No binary-pool GC. Refcounts are unaffected.
    ///
    /// To *clear* `last_access_time` (for example the Keys-app
    /// "clear last-access" button), route through
    /// [`Self::edit_entry`] +
    /// [`crate::model::EntryEditor::set_last_access_time`] with `None`.
    ///
    /// # Errors
    ///
    /// - [`ModelError::EntryNotFound`] if `id` is not in the vault.
    pub fn touch_entry(&mut self, id: EntryId) -> Result<(), ModelError> {
        let now = self.state.clock.now();
        let entry =
            find_entry_mut(&mut self.state.vault.root, id).ok_or(ModelError::EntryNotFound(id))?;
        entry.times.last_access_time = Some(now);
        Ok(())
    }

    /// Restore the live entry's content from its own
    /// `history[history_index]`, with the pre-restore state optionally
    /// stamped into history per `policy`.
    ///
    /// Semantically: "revert this entry to how it looked at snapshot
    /// N". Used by Keys.app's
    /// `EntryDetailView.swift:481` ("restore this revision") button.
    ///
    /// Bookkeeping:
    ///
    /// 1. Verify `history_index < entry.history.len()`; out-of-range
    ///    rejects with [`ModelError::HistoryIndexOutOfRange`] before
    ///    any state changes.
    /// 2. If `policy` says snapshot (the same rules as
    ///    [`Self::edit_entry`]), push `entry.clone()` into
    ///    `entry.history` with that snapshot's own history cleared —
    ///    KeePass never nests. This captures the content we're about
    ///    to overwrite so the user can undo the restore later.
    /// 3. Overwrite the live entry's content fields from the target
    ///    snapshot. "Content" is the user-visible surface: title,
    ///    username, password, url, notes, tags, custom fields, icon
    ///    id + custom-icon UUID, override URL, foreground / background
    ///    colours, quality-check flag, the expiry pair
    ///    (`times.expires` + `times.expiry_time`, treated atomically),
    ///    auto-type block, and the attachment reference list (refs
    ///    only — binary bytes live in [`crate::model::Vault::binaries`]
    ///    and are refcount-tracked across history, so a restored ref
    ///    can't dangle).
    /// 4. Fields NOT overwritten: `id` (identity),
    ///    `times.{creation,last_access,location_changed,usage_count,
    ///    last_modification_time}` (library owns), `history` (we're
    ///    mutating it, not restoring it), `previous_parent_group`
    ///    (tree-movement state, not content), `custom_data` (plugin
    ///    / client state that may have advanced since the snapshot),
    ///    and `unknown_xml` (foreign-writer opaque data — see below).
    /// 5. Stamp `entry.times.last_modification_time = clock.now()`.
    /// 6. Truncate `entry.history` per `Meta::history_max_items` /
    ///    `history_max_size`. A newly-pushed pre-restore snapshot may
    ///    push the count over the cap; truncation drops oldest first.
    /// 7. Run the binary-pool refcount GC — truncation can drop a snapshot
    ///    that was the only remaining reference to a pool binary, so
    ///    we collect the pool after history shrinks.
    ///
    /// **`unknown_xml` is intentionally left on the live entry.** By
    /// construction these are XML subtrees the decoder didn't
    /// recognise — foreign-writer or future-version data we have no
    /// semantic grounds to classify as content. Rolling them back to
    /// the snapshot risks destroying additions that arrived after the
    /// snapshot was taken. Same reasoning as `custom_data` above:
    /// restore is a *content* operation; opaque external channels are
    /// preserved on the live entry.
    ///
    /// # Errors
    ///
    /// - [`ModelError::EntryNotFound`] if `id` is not in the vault.
    /// - [`ModelError::HistoryIndexOutOfRange`] if `history_index`
    ///   is `>= entry.history.len()`.
    pub fn restore_entry_from_history(
        &mut self,
        id: EntryId,
        history_index: usize,
        policy: HistoryPolicy,
    ) -> Result<(), ModelError> {
        // Hoist off `self.state` before the `&mut Entry` borrow, same
        // reason as `edit_entry`.
        let now = self.state.clock.now();
        let history_max_items = self.state.vault.meta.history_max_items;
        let history_max_size = self.state.vault.meta.history_max_size;

        let entry =
            find_entry_mut(&mut self.state.vault.root, id).ok_or(ModelError::EntryNotFound(id))?;

        if history_index >= entry.history.len() {
            return Err(ModelError::HistoryIndexOutOfRange {
                id,
                index: history_index,
                len: entry.history.len(),
            });
        }

        // Clone the target snapshot out before mutating history — once
        // we push the pre-restore snapshot the index shifts.
        let snap = entry.history[history_index].clone();

        if should_snapshot_now(policy, &entry.history, now) {
            let mut pre_restore = entry.clone();
            // KeePass never nests history; the snapshot we're pushing
            // represents the live entry at call time, not "live + all
            // its prior history".
            pre_restore.history.clear();
            entry.history.push(pre_restore);
        }

        // ---- Restore content -----------------------------------------
        // Explicit field-by-field copy so the restore set is auditable
        // at this call site. Excluded fields are documented on the
        // method; if a new field lands on `Entry`, the reviewer sees
        // this block and decides its restore policy deliberately.
        entry.title = snap.title;
        entry.username = snap.username;
        entry.password = snap.password;
        entry.url = snap.url;
        entry.notes = snap.notes;
        entry.tags = snap.tags;
        entry.custom_fields = snap.custom_fields;
        entry.attachments = snap.attachments;
        entry.foreground_color = snap.foreground_color;
        entry.background_color = snap.background_color;
        entry.override_url = snap.override_url;
        entry.custom_icon_uuid = snap.custom_icon_uuid;
        entry.icon_id = snap.icon_id;
        entry.quality_check = snap.quality_check;
        entry.auto_type = snap.auto_type;
        // Expiry is wire-split into two fields, but semantically one —
        // the `set_expiry` setter unifies them at the API boundary and
        // we copy them atomically here so a stale `expires=false` can't
        // linger alongside a freshly-restored `expiry_time`.
        entry.times.expires = snap.times.expires;
        entry.times.expiry_time = snap.times.expiry_time;

        // Stamp the restore as an edit, so UIs that sort by
        // last-modification show this entry at the top.
        entry.times.last_modification_time = Some(now);

        truncate_history(&mut entry.history, history_max_items, history_max_size);

        // End the entry borrow so the vault is accessible again for
        // pool GC.
        let _ = entry;
        gc_binaries_pool(&mut self.state.vault);

        Ok(())
    }

    // -----------------------------------------------------------------
    // Custom-icon pool
    // -----------------------------------------------------------------

    /// Insert a custom icon into [`crate::model::Meta::custom_icons`],
    /// returning the UUID the caller can then hand to
    /// [`crate::model::EntryEditor::set_custom_icon`] /
    /// [`crate::model::GroupEditor::set_custom_icon`].
    ///
    /// Deduplicated by content hash: if the pool already holds an
    /// icon with identical bytes (SHA-256 match), that icon's
    /// existing UUID is returned and the pool is left unchanged.
    /// Dedup is idempotent — the existing icon's `name` and
    /// `last_modified` fields are **not** overwritten, so a caller
    /// that has previously labelled an icon doesn't lose the label
    /// by re-adding the bytes.
    ///
    /// Stamps [`crate::model::Meta::settings_changed`] on a fresh
    /// insert; a dedup hit does not stamp (nothing changed).
    pub fn add_custom_icon(&mut self, data: Vec<u8>) -> uuid::Uuid {
        let (uuid, inserted) = add_or_dedup_icon(&mut self.state.vault, data);
        if inserted {
            self.stamp_settings_changed();
        }
        uuid
    }

    /// Remove the custom icon with the given UUID from
    /// [`crate::model::Meta::custom_icons`]. Returns `true` if the
    /// icon existed.
    ///
    /// Does **not** unset `entry.custom_icon_uuid` /
    /// `group.custom_icon_uuid` on records still referencing the
    /// removed icon. Those refs dangle in the in-memory model until
    /// the next [`Self::save_to_bytes`] call, where the save path
    /// GC silently resets every dangling `custom_icon_uuid` to
    /// `None` so the emitted bytes carry no unresolvable references.
    /// Callers who want the model to match the save-path output
    /// should walk the tree themselves; the library's on-disk
    /// invariant — "every `<CustomIconUUID>` resolves in
    /// `<CustomIcons>`" — is maintained either way.
    ///
    /// Stamps [`crate::model::Meta::settings_changed`] on success;
    /// a "no such icon" call does not stamp (nothing changed).
    pub fn remove_custom_icon(&mut self, id: uuid::Uuid) -> bool {
        let before = self.state.vault.meta.custom_icons.len();
        self.state.vault.meta.custom_icons.retain(|c| c.uuid != id);
        if self.state.vault.meta.custom_icons.len() < before {
            self.stamp_settings_changed();
            true
        } else {
            false
        }
    }

    /// Borrow the raw bytes for the custom icon identified by `id`.
    /// Returns `None` if no such icon is registered.
    ///
    /// Bytes are opaque to the library — typically PNG, but the
    /// format is whatever the inserting client wrote. The decoder
    /// already base64-decoded them on read, so callers get the
    /// image payload directly without a second decode step.
    #[must_use]
    pub fn custom_icon(&self, id: uuid::Uuid) -> Option<&[u8]> {
        self.state
            .vault
            .meta
            .custom_icons
            .iter()
            .find(|c| c.uuid == id)
            .map(|c| c.data.as_slice())
    }

    // -----------------------------------------------------------------
    // Cross-vault export / import
    // -----------------------------------------------------------------

    /// Produce a self-contained snapshot of the entry identified by
    /// `id`, suitable for importing into a different (or the same)
    /// vault via [`Self::import_entry`].
    ///
    /// The returned [`PortableEntry`] carries the entry, every one
    /// of its history snapshots, the full decrypted bytes of every
    /// binary referenced by the entry **or** any history snapshot,
    /// and every custom icon referenced by the entry **or** any
    /// history snapshot. The destination vault therefore doesn't
    /// need to share the source's pools — dedup against the
    /// destination's pools happens during `import_entry`.
    ///
    /// Read-only: does not mutate `self`, does not stamp any
    /// timestamps, does not touch the binary or custom-icon pools.
    ///
    /// # Errors
    ///
    /// - [`ModelError::EntryNotFound`] if `id` is not in the vault.
    pub fn export_entry(&self, id: EntryId) -> Result<PortableEntry, ModelError> {
        let entry = find_entry(&self.state.vault.root, id).ok_or(ModelError::EntryNotFound(id))?;

        // Collect the set of binary ref_ids referenced by the entry
        // or any of its history snapshots. Same live+history walk
        // as `collect_attachment_refs` (defined for pool GC).
        let mut binary_refs: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for a in &entry.attachments {
            binary_refs.insert(a.ref_id);
        }
        for snap in &entry.history {
            for a in &snap.attachments {
                binary_refs.insert(a.ref_id);
            }
        }
        let mut binaries: Vec<(u32, Binary)> = binary_refs
            .into_iter()
            .filter_map(|r| {
                self.state
                    .vault
                    .binaries
                    .get(r as usize)
                    .map(|b| (r, b.clone()))
            })
            .collect();
        binaries.sort_by_key(|(r, _)| *r);

        // Collect the set of custom-icon UUIDs referenced by live +
        // history, then clone the full CustomIcon record for each.
        let mut icon_refs: std::collections::HashSet<uuid::Uuid> = std::collections::HashSet::new();
        if let Some(u) = entry.custom_icon_uuid {
            icon_refs.insert(u);
        }
        for snap in &entry.history {
            if let Some(u) = snap.custom_icon_uuid {
                icon_refs.insert(u);
            }
        }
        let custom_icons: Vec<crate::model::CustomIcon> = self
            .state
            .vault
            .meta
            .custom_icons
            .iter()
            .filter(|c| icon_refs.contains(&c.uuid))
            .cloned()
            .collect();

        Ok(PortableEntry {
            entry: entry.clone(),
            binaries,
            custom_icons,
        })
    }

    /// Insert a [`PortableEntry`] under `parent`.
    ///
    /// When `mint_new_uuid` is `true`, the imported entry — and
    /// every one of its history snapshots — receives a fresh UUID
    /// via [`crate::model::Vault`]-wide collision avoidance. This is
    /// the canonical cross-vault-move path: the entry-as-it-appears-
    /// in-this-vault is a newly-created record, distinct identity
    /// from the source's.
    ///
    /// When `mint_new_uuid` is `false`, the original UUIDs are
    /// preserved; import fails with [`ModelError::DuplicateUuid`]
    /// (before any destination state is mutated) if the entry's
    /// UUID **or** any history snapshot's UUID already exists in
    /// this vault. Used by merge flows that treat identical UUIDs
    /// across vaults as the same record.
    ///
    /// Binary dedup: each referenced binary is content-hash-compared
    /// against [`crate::model::Vault::binaries`]; matches reuse the
    /// existing pool slot, misses are appended. The entry's and
    /// every history snapshot's `attachments[].ref_id` are remapped
    /// to destination-vault indices before insertion.
    ///
    /// Custom-icon dedup: when `mint_new_uuid = false`, icons are
    /// deduped by UUID; when `mint_new_uuid = true`, icons are
    /// deduped by content hash via [`Self::add_custom_icon`] (so the
    /// icon's save-time GC discipline continues to hold). In both
    /// paths the entry's and history snapshots' `custom_icon_uuid`
    /// refs are remapped.
    ///
    /// Bookkeeping (same shape as [`Self::add_entry`] for the
    /// imported live entry):
    ///
    /// - All `times.*` stamped to [`Self::clock`]`.now()` —
    ///   `creation_time`, `last_modification_time`,
    ///   `last_access_time`, `location_changed`. `expires` and
    ///   `expiry_time` are content fields and preserved from the
    ///   source. `usage_count` reset to 0 (the entry's usage starts
    ///   fresh in this vault).
    /// - `previous_parent_group = None`.
    /// - **History-snapshot timestamps preserved verbatim** —
    ///   those snapshots describe edits that happened on the source
    ///   before the import, and rewriting them would be a lie.
    ///
    /// Does not stamp [`crate::model::Meta::settings_changed`] —
    /// adding entries is not a settings change, same as
    /// [`Self::add_entry`].
    ///
    /// # Errors
    ///
    /// - [`ModelError::GroupNotFound`] if `parent` isn't in the vault.
    /// - [`ModelError::DuplicateUuid`] if `mint_new_uuid = false`
    ///   and any UUID from the incoming entry (live or history)
    ///   collides with an existing vault UUID. The destination is
    ///   untouched on this failure.
    ///
    /// # Panics
    ///
    /// Does not panic under any input. The second `find_group_mut`
    /// call after UUID validation is `.expect()`ed because the
    /// first call has already proved the parent exists.
    pub fn import_entry(
        &mut self,
        parent: GroupId,
        mut entry: PortableEntry,
        mint_new_uuid: bool,
    ) -> Result<EntryId, ModelError> {
        if find_group(&self.state.vault.root, parent).is_none() {
            return Err(ModelError::GroupNotFound(parent));
        }

        // Validate (or mint) UUIDs for the live entry + every
        // history snapshot before any destination mutation.
        // `DuplicateUuid` must fail cleanly.
        if mint_new_uuid {
            entry.entry.id = EntryId(fresh_uuid(&self.state.vault));
            for snap in &mut entry.entry.history {
                snap.id = EntryId(fresh_uuid(&self.state.vault));
            }
        } else {
            if uuid_in_use(&self.state.vault, entry.entry.id.0) {
                return Err(ModelError::DuplicateUuid(entry.entry.id.0));
            }
            for snap in &entry.entry.history {
                if uuid_in_use(&self.state.vault, snap.id.0) {
                    return Err(ModelError::DuplicateUuid(snap.id.0));
                }
            }
        }

        // Binary-pool remap: content-hash dedup against
        // `self.state.vault.binaries`; insert misses, reuse hits.
        let mut binary_remap: HashMap<u32, u32> = HashMap::new();
        for (src_ref, bin) in entry.binaries.drain(..) {
            let dst_ref = insert_or_dedup_binary(&mut self.state.vault, bin);
            binary_remap.insert(src_ref, dst_ref);
        }

        // Custom-icon pool remap: UUID-dedup on the mint_new_uuid=false
        // path, content-hash-dedup via `add_custom_icon` on the
        // mint_new_uuid=true path.
        let mut icon_remap: HashMap<uuid::Uuid, uuid::Uuid> = HashMap::new();
        if mint_new_uuid {
            for icon in entry.custom_icons.drain(..) {
                let dst_uuid = self.add_custom_icon(icon.data.clone());
                icon_remap.insert(icon.uuid, dst_uuid);
            }
        } else {
            for icon in entry.custom_icons.drain(..) {
                let src_uuid = icon.uuid;
                let already_present = self
                    .state
                    .vault
                    .meta
                    .custom_icons
                    .iter()
                    .any(|c| c.uuid == src_uuid);
                if !already_present {
                    self.state.vault.meta.custom_icons.push(icon);
                    // No `settings_changed` stamp here — adding an
                    // entry (and its referenced icons) is shaped
                    // like `add_entry`, which doesn't stamp Meta.
                }
                icon_remap.insert(src_uuid, src_uuid);
            }
        }

        // Apply remaps to the live entry and every history snapshot.
        let now = self.state.clock.now();
        remap_entry_refs(&mut entry.entry, &binary_remap, &icon_remap);
        for snap in &mut entry.entry.history {
            remap_entry_refs(snap, &binary_remap, &icon_remap);
        }

        // Stamp live-entry bookkeeping per MUTATION.md invariants.
        entry.entry.times.creation_time = Some(now);
        entry.entry.times.last_modification_time = Some(now);
        entry.entry.times.last_access_time = Some(now);
        entry.entry.times.location_changed = Some(now);
        entry.entry.times.usage_count = 0;
        entry.entry.previous_parent_group = None;

        let new_id = entry.entry.id;
        let target = find_group_mut(&mut self.state.vault.root, parent)
            .expect("parent existence checked at the top of this method");
        target.entries.push(entry.entry);
        Ok(new_id)
    }

    // -----------------------------------------------------------------
    // Recycle bin helpers
    // -----------------------------------------------------------------

    /// Soft-delete an entry by moving it into the vault's recycle
    /// bin group, creating the bin lazily on first use.
    ///
    /// - **Happy path** (bin exists or will be created,
    ///   `recycle_bin_enabled` is `true`): calls
    ///   [`Self::move_entry`] under the hood, so the entry gets
    ///   `times.location_changed = clock.now()` + `previous_parent_group
    ///   = Some(old_parent)`. No `DeletedObject` is emitted — recycling
    ///   is a move, not a delete.
    /// - **Bin disabled and no bin group exists**
    ///   (`meta.recycle_bin_enabled = false` **and**
    ///   `meta.recycle_bin_uuid` is `None`): falls back to
    ///   [`Self::delete_entry`] (hard delete + `DeletedObject`
    ///   tombstone). A bin that exists with `enabled = false` is
    ///   still used for soft-delete — the flag gates bin
    ///   **creation**, not bin **use**.
    /// - **Already inside the bin**: short-circuits; no mutation.
    ///
    /// Returns `Ok(Some(bin_id))` on a real move, or `Ok(None)` on
    /// any of three distinct non-move outcomes:
    /// 1. The entry was already inside the bin.
    /// 2. `recycle_bin_enabled = false` and the fallback hard-delete
    ///    ran.
    /// 3. _(Reserved — no other case produces `None` today.)_
    ///
    /// Callers can disambiguate by inspecting
    /// `meta.recycle_bin_enabled` + whether the entry still exists
    /// after the call.
    ///
    /// # Lazy bin creation
    ///
    /// If `meta.recycle_bin_uuid` is `None` — or points at a group
    /// that no longer exists (dangling) — a fresh group is created
    /// under the root with `name = "Recycle Bin"`, `icon_id = 43`
    /// (KeePass's built-in "Recycle Bin" icon),
    /// `enable_auto_type = Some(false)`, `enable_searching = Some(false)`.
    /// Meta bookkeeping: `recycle_bin_enabled = true`,
    /// `recycle_bin_uuid = Some(new_id)`,
    /// `recycle_bin_changed = clock.now()`, plus a
    /// `meta.settings_changed` stamp.
    ///
    /// # Errors
    ///
    /// - [`ModelError::EntryNotFound`] if `id` is absent.
    pub fn recycle_entry(&mut self, id: EntryId) -> Result<Option<GroupId>, ModelError> {
        // Validate existence + get the entry's current parent group.
        let parent =
            entry_parent_group(&self.state.vault.root, id).ok_or(ModelError::EntryNotFound(id))?;

        // `recycle_bin_enabled = false` → hard delete, no bin.
        if !self.state.vault.meta.recycle_bin_enabled
            && self.state.vault.meta.recycle_bin_uuid.is_none()
        {
            // Only fall through to hard-delete when BOTH enabled is
            // false AND no bin exists. If a bin exists (even with
            // enabled=false), respect it — matches KeePassXC's
            // "bin exists, you can still use it" flexibility.
            self.delete_entry(id)?;
            return Ok(None);
        }

        // Already inside the bin? Walk ancestors from the parent
        // group up to root; any ancestor == bin → no-op.
        if let Some(bin_id) = self.state.vault.meta.recycle_bin_uuid {
            if find_group(&self.state.vault.root, bin_id).is_some()
                && group_is_descendant_of(&self.state.vault.root, parent, bin_id)
            {
                return Ok(None);
            }
        }

        let bin_id = self.find_or_create_recycle_bin()?;
        self.move_entry(id, bin_id)?;
        Ok(Some(bin_id))
    }

    /// Soft-delete a group (and its subtree) into the recycle bin.
    /// Same shape as [`Self::recycle_entry`] but for groups.
    ///
    /// # Errors
    ///
    /// - [`ModelError::GroupNotFound`] if `id` is absent.
    /// - [`ModelError::CannotDeleteRoot`] if `id` is the root.
    /// - [`ModelError::CircularMove`] if `id` is the recycle bin
    ///   itself — "group can't be its own ancestor" is the wire
    ///   invariant, and recycling the bin into itself trips it.
    pub fn recycle_group(&mut self, id: GroupId) -> Result<Option<GroupId>, ModelError> {
        if find_group(&self.state.vault.root, id).is_none() {
            return Err(ModelError::GroupNotFound(id));
        }
        if id == self.state.vault.root.id {
            return Err(ModelError::CannotDeleteRoot);
        }

        // Same fallback logic as `recycle_entry`.
        if !self.state.vault.meta.recycle_bin_enabled
            && self.state.vault.meta.recycle_bin_uuid.is_none()
        {
            self.delete_group(id)?;
            return Ok(None);
        }

        // Is `id` the bin itself? → CircularMove.
        if let Some(bin_id) = self.state.vault.meta.recycle_bin_uuid {
            if bin_id == id && find_group(&self.state.vault.root, bin_id).is_some() {
                return Err(ModelError::CircularMove {
                    moving: id,
                    new_parent: bin_id,
                });
            }
            // Already inside the bin?
            if find_group(&self.state.vault.root, bin_id).is_some()
                && group_is_descendant_of(&self.state.vault.root, id, bin_id)
            {
                return Ok(None);
            }
        }

        let bin_id = self.find_or_create_recycle_bin()?;
        self.move_group(id, bin_id)?;
        Ok(Some(bin_id))
    }

    /// Permanently delete every direct child of the recycle bin.
    /// Each removed entry and subgroup lands as a `DeletedObject`
    /// tombstone in `vault.deleted_objects`; the bin group itself
    /// survives (empty).
    ///
    /// Returns the count of **direct** children removed from the
    /// bin. The recursive tombstone cascade — one `DeletedObject`
    /// per nested entry and subgroup, emitted by
    /// [`Self::delete_entry`] / [`Self::delete_group`] — is
    /// observable via `vault.deleted_objects.len()` delta, not via
    /// this return value.
    ///
    /// `Ok(0)` if no recycle bin exists (either
    /// `meta.recycle_bin_uuid` is `None` or it points at a group
    /// that no longer resolves). No error, just a no-op.
    pub fn empty_recycle_bin(&mut self) -> Result<usize, ModelError> {
        let Some(bin_id) = self.state.vault.meta.recycle_bin_uuid else {
            return Ok(0);
        };
        // Snapshot direct-child ids BEFORE mutating — can't iterate
        // `&mut Vec` while calling `&mut self` delete methods. A
        // dangling `recycle_bin_uuid` resolves to `None` here and
        // we early-return 0.
        let Some(bin) = find_group(&self.state.vault.root, bin_id) else {
            return Ok(0);
        };
        let entry_ids: Vec<EntryId> = bin.entries.iter().map(|e| e.id).collect();
        let group_ids: Vec<GroupId> = bin.groups.iter().map(|g| g.id).collect();
        let count = entry_ids.len() + group_ids.len();

        for eid in entry_ids {
            self.delete_entry(eid)?;
        }
        for gid in group_ids {
            self.delete_group(gid)?;
        }
        Ok(count)
    }

    /// Resolve the existing recycle bin group id, or create one
    /// lazily under the root if none exists (or if the current
    /// `recycle_bin_uuid` dangles). See [`Self::recycle_entry`] for
    /// the lazy-creation invariants.
    fn find_or_create_recycle_bin(&mut self) -> Result<GroupId, ModelError> {
        if let Some(bin_id) = self.state.vault.meta.recycle_bin_uuid {
            if find_group(&self.state.vault.root, bin_id).is_some() {
                return Ok(bin_id);
            }
            // Dangling — fall through and mint a fresh bin. The
            // stale `recycle_bin_uuid` is about to be overwritten
            // below.
        }
        let root = self.state.vault.root.id;
        let bin_id = self.add_group(
            root,
            NewGroup::new("Recycle Bin")
                .icon_id(43)
                .enable_auto_type(Some(false))
                .enable_searching(Some(false)),
        )?;
        let now = self.state.clock.now();
        self.state.vault.meta.recycle_bin_enabled = true;
        self.state.vault.meta.recycle_bin_uuid = Some(bin_id);
        self.state.vault.meta.recycle_bin_changed = Some(now);
        self.stamp_settings_changed();
        Ok(bin_id)
    }

    /// Serialise this unlocked database back to a KDBX byte stream —
    /// the byte-level inverse of [`Kdbx::<HeaderRead>::unlock`].
    ///
    /// Reuses the outer-header framing (cipher, master seed, KDF
    /// parameters, IV) that was parsed at unlock time, plus the
    /// transformed key cached in the [`Unlocked`] state so no second
    /// round of Argon2 is needed.
    ///
    /// # Supported configurations
    ///
    /// Both **KDBX3 and KDBX4** are supported, with either the
    /// **AES-256-CBC** or **ChaCha20** outer cipher (whichever the
    /// source file's outer header declares). Twofish-CBC is rejected
    /// at save time with [`FormatError::MalformedHeader`] — the same
    /// path `unlock` already takes for that cipher.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Xml`] on XML encode failures,
    /// [`Error::Format`] on framing failures (inner header write,
    /// TLV overflow, compression failure), or [`Error::Crypto`] on
    /// cipher / IV mismatches.
    ///
    /// # Round-trip guarantee
    ///
    /// `kdbx.save_to_bytes()` followed by `Kdbx::open_from_bytes(...)`
    /// followed by `.read_header()?.unlock(same_key)?` yields a
    /// [`Vault`] equal to the one currently in this [`Kdbx`]. Byte-
    /// exact equality with the original source file is **not**
    /// guaranteed: the XML encoder canonicalises formatting, the
    /// VarDictionary encoder canonicalises key order, and the outer
    /// header always emits tags in ascending numeric order.
    pub fn save_to_bytes(&self) -> Result<Vec<u8>, Error> {
        do_save(self.signature, self.version, &self.state)
    }

    /// Insert a new [`Group`] under the parent identified by
    /// `parent`.
    ///
    /// Mirrors [`Self::add_entry`]: the library owns UUID generation
    /// (unless the builder set one via [`NewGroup::with_uuid`]),
    /// fills in every [`Timestamps`] field from [`Self::clock`],
    /// sets `previous_parent_group = None`, and appends the group to
    /// the parent's child list. Returns the new group's [`GroupId`].
    ///
    /// # Errors
    ///
    /// - [`ModelError::GroupNotFound`] if `parent` is not in the vault.
    /// - [`ModelError::DuplicateUuid`] if the builder supplied a UUID
    ///   that is already in use anywhere in the vault.
    ///
    /// # Panics
    ///
    /// Does not panic under any input. The second `find_group_mut`
    /// call is `.expect()`ed because the first call has already
    /// proved the parent exists.
    pub fn add_group(
        &mut self,
        parent: GroupId,
        template: NewGroup,
    ) -> Result<GroupId, ModelError> {
        let uuid = match template.uuid {
            Some(u) => {
                if uuid_in_use(&self.state.vault, u) {
                    return Err(ModelError::DuplicateUuid(u));
                }
                u
            }
            None => fresh_uuid(&self.state.vault),
        };

        if find_group_mut(&mut self.state.vault.root, parent).is_none() {
            return Err(ModelError::GroupNotFound(parent));
        }

        let now = self.state.clock.now();
        let group = Group {
            id: GroupId(uuid),
            name: template.name,
            notes: template.notes,
            groups: Vec::new(),
            entries: Vec::new(),
            is_expanded: true,
            default_auto_type_sequence: String::new(),
            enable_auto_type: template.enable_auto_type,
            enable_searching: template.enable_searching,
            custom_data: Vec::new(),
            previous_parent_group: None,
            last_top_visible_entry: None,
            custom_icon_uuid: None,
            times: Timestamps {
                creation_time: Some(now),
                last_modification_time: Some(now),
                last_access_time: Some(now),
                location_changed: Some(now),
                expiry_time: None,
                expires: false,
                usage_count: 0,
            },
            icon_id: template.icon_id,
            unknown_xml: Vec::new(),
        };

        let target = find_group_mut(&mut self.state.vault.root, parent)
            .expect("parent existence checked above");
        target.groups.push(group);
        Ok(GroupId(uuid))
    }

    /// Recursively delete the group with the given id.
    ///
    /// Every entry and every subgroup under the target gets its own
    /// [`DeletedObject`] tombstone (stamped from [`Self::clock`])
    /// before the subtree is removed, so a peer replica merging
    /// against this vault can tell deleted records apart from
    /// never-seen ones.
    ///
    /// # Errors
    ///
    /// - [`ModelError::CannotDeleteRoot`] if `id` is the root group's id.
    /// - [`ModelError::GroupNotFound`] if `id` is not in the vault.
    pub fn delete_group(&mut self, id: GroupId) -> Result<(), ModelError> {
        if self.state.vault.root.id == id {
            return Err(ModelError::CannotDeleteRoot);
        }
        let now = self.state.clock.now();
        let removed = remove_group_with_parent(&mut self.state.vault.root, id)
            .ok_or(ModelError::GroupNotFound(id))?;
        // Tombstone every entry and subgroup recursively, in addition
        // to the group itself.
        let tombstones = collect_subtree_tombstones(&removed, now);
        self.state.vault.deleted_objects.extend(tombstones);
        Ok(())
    }

    /// Move a group from its current parent to `new_parent`.
    ///
    /// Bookkeeping applied automatically:
    /// - `group.times.location_changed = self.clock().now()`
    /// - `group.previous_parent_group = Some(old_parent)`
    /// - **Cycle rejection.** A move that would make `id` a descendant
    ///   of itself (i.e. `new_parent` is `id` or anywhere under `id`'s
    ///   subtree) returns [`ModelError::CircularMove`] and leaves the
    ///   tree untouched.
    ///
    /// # Errors
    ///
    /// - [`ModelError::CannotDeleteRoot`] if `id` is the root group's
    ///   id (the root has no parent and cannot be moved).
    /// - [`ModelError::GroupNotFound`] if either `id` or `new_parent`
    ///   is missing.
    /// - [`ModelError::CircularMove`] if the move would create a cycle.
    ///
    /// # Panics
    ///
    /// Does not panic under any input. The final `find_group_mut`
    /// call is `.expect()`ed because the destination's existence was
    /// already proved earlier in the function.
    pub fn move_group(&mut self, id: GroupId, new_parent: GroupId) -> Result<(), ModelError> {
        if self.state.vault.root.id == id {
            // Root has no parent and reparenting it would orphan the
            // whole vault.
            return Err(ModelError::CannotDeleteRoot);
        }

        // Check the destination exists before touching anything.
        if find_group(&self.state.vault.root, new_parent).is_none() {
            return Err(ModelError::GroupNotFound(new_parent));
        }

        // Cycle check: walk `id`'s subtree (including `id` itself)
        // and reject if `new_parent` lives inside it.
        let Some(source_subtree) = find_group(&self.state.vault.root, id) else {
            return Err(ModelError::GroupNotFound(id));
        };
        if subtree_contains(source_subtree, new_parent) {
            return Err(ModelError::CircularMove {
                moving: id,
                new_parent,
            });
        }

        let (mut group, old_parent) = remove_group_with_parent_pair(&mut self.state.vault.root, id)
            .ok_or(ModelError::GroupNotFound(id))?;
        let now = self.state.clock.now();
        group.previous_parent_group = Some(old_parent);
        group.times.location_changed = Some(now);

        let target = find_group_mut(&mut self.state.vault.root, new_parent)
            .expect("destination existence checked above");
        target.groups.push(group);
        Ok(())
    }

    /// Field-level edit on a single group, with one automatic
    /// `last_modification_time` stamp after the closure returns.
    ///
    /// Groups don't carry history, so there is no `HistoryPolicy`
    /// parameter and no snapshot logic — the closure just gets a
    /// [`GroupEditor`], the library stamps the timestamp, and the
    /// edit is committed.
    ///
    /// # Errors
    ///
    /// - [`ModelError::GroupNotFound`] if `id` is not in the vault.
    pub fn edit_group<R>(
        &mut self,
        id: GroupId,
        f: impl FnOnce(&mut GroupEditor<'_>) -> R,
    ) -> Result<R, ModelError> {
        let now = self.state.clock.now();
        let group =
            find_group_mut(&mut self.state.vault.root, id).ok_or(ModelError::GroupNotFound(id))?;
        let result = {
            let mut editor = GroupEditor::new(group);
            f(&mut editor)
        };
        group.times.last_modification_time = Some(now);
        Ok(result)
    }

    // -----------------------------------------------------------------
    // Meta setters
    // -----------------------------------------------------------------
    //
    // Each setter writes the requested field on `vault.meta` and
    // stamps `meta.settings_changed = clock.now()`. The library never
    // touches the per-field `*Changed` timestamps (e.g.
    // `database_name_changed`) — those are KeePass's own field-level
    // history and are out of scope for this slice.

    /// Set the user-visible vault name.
    pub fn set_database_name(&mut self, name: impl Into<String>) {
        self.state.vault.meta.database_name = name.into();
        self.stamp_settings_changed();
    }

    /// Set the user-visible free-text vault description.
    pub fn set_database_description(&mut self, description: impl Into<String>) {
        self.state.vault.meta.database_description = description.into();
        self.stamp_settings_changed();
    }

    /// Set the default username used for new entries.
    pub fn set_default_username(&mut self, username: impl Into<String>) {
        self.state.vault.meta.default_username = username.into();
        self.stamp_settings_changed();
    }

    /// Set the vault-level colour swatch (hex `"#RRGGBB"`). Empty
    /// string falls back to the host client's default colour.
    pub fn set_color(&mut self, hex: impl Into<String>) {
        self.state.vault.meta.color = hex.into();
        self.stamp_settings_changed();
    }

    /// Configure the recycle bin: whether soft-delete is enabled, and
    /// which group acts as the bin. Pass `None` to clear the bin
    /// reference (the on-disk encoding then surfaces as either an
    /// absent or all-zero UUID).
    pub fn set_recycle_bin(&mut self, enabled: bool, group: Option<GroupId>) {
        self.state.vault.meta.recycle_bin_enabled = enabled;
        self.state.vault.meta.recycle_bin_uuid = group;
        self.stamp_settings_changed();
    }

    /// Cap entry-history length. `-1` means unlimited.
    pub fn set_history_max_items(&mut self, max: i32) {
        self.state.vault.meta.history_max_items = max;
        self.stamp_settings_changed();
    }

    /// Cap entry-history byte size. `-1` means unlimited.
    pub fn set_history_max_size(&mut self, max: i64) {
        self.state.vault.meta.history_max_size = max;
        self.stamp_settings_changed();
    }

    /// Set how long to keep entry snapshots before the host client
    /// prunes them, in days.
    pub fn set_maintenance_history_days(&mut self, days: u32) {
        self.state.vault.meta.maintenance_history_days = days;
        self.stamp_settings_changed();
    }

    /// Set the recommended-master-key-change interval, in days.
    /// `-1` disables the recommendation.
    pub fn set_master_key_change_rec(&mut self, days: i64) {
        self.state.vault.meta.master_key_change_rec = days;
        self.stamp_settings_changed();
    }

    /// Set the forced-master-key-change interval, in days.
    /// `-1` disables the force policy.
    pub fn set_master_key_change_force(&mut self, days: i64) {
        self.state.vault.meta.master_key_change_force = days;
        self.stamp_settings_changed();
    }

    /// Stamp [`crate::model::Meta::settings_changed`] from the
    /// injected clock. Shared by every setter above so a single
    /// place owns the side-effect.
    fn stamp_settings_changed(&mut self) {
        self.state.vault.meta.settings_changed = Some(self.state.clock.now());
    }

    /// Replace the master key.
    ///
    /// Rotates everything that participates in deriving the cipher
    /// and HMAC keys from the composite key, so an attacker who
    /// captured the previous file can't decrypt the new one even if
    /// they later learn the new password:
    ///
    /// - Fresh [`MasterSeed`] (32 bytes from `getrandom`).
    /// - Fresh [`EncryptionIv`] (length-matched to the configured
    ///   outer cipher: 16 bytes for AES-256-CBC, 12 bytes for
    ///   ChaCha20).
    /// - KDBX3: fresh [`TransformSeed`] (32 bytes) for the AES-KDF.
    /// - KDBX4: fresh `S` value in the KDF parameter VarDictionary
    ///   — Argon2 salt or AES-KDF seed depending on which KDF the
    ///   header configured. The original size is preserved (writers
    ///   commonly emit 32 bytes for both, but the spec only requires
    ///   ≥ 8 for Argon2 salt, so we honour whatever size was there).
    ///
    /// The transformed key is then re-derived against `new_key` +
    /// the new KDF parameters and cached on the [`Unlocked`] state,
    /// so the next `save_to_bytes` re-uses it without paying the
    /// (expensive) KDF cost again.
    ///
    /// Bookkeeping side-effects: `Meta::master_key_changed` and
    /// `Meta::settings_changed` are both stamped from
    /// [`Self::clock`].
    ///
    /// **Does not touch entries.** Stored protected values were
    /// XOR-encoded against the inner-stream cipher (whose key is the
    /// `protected_stream_key` / inner-header key, *not* the master
    /// key); rotating the master key has no effect on them.
    ///
    /// # Errors
    ///
    /// - [`Error::Crypto`] if the KDF rejects the new key (e.g. the
    ///   Argon2 implementation returns an internal error).
    /// - [`Error::Format`] if the existing KDF-parameters blob is
    ///   malformed beyond what `parse` already accepts (effectively
    ///   unreachable from a successfully unlocked file).
    pub fn rekey(&mut self, new_key: &CompositeKey) -> Result<(), Error> {
        // --- Fresh seeds ---------------------------------------------
        let mut new_master_seed = [0u8; 32];
        getrandom::fill(&mut new_master_seed).map_err(|_| Error::Crypto(CryptoError::Decrypt))?;

        let iv_len = self.state.outer_header.encryption_iv.0.len();
        let mut new_iv = vec![0u8; iv_len];
        getrandom::fill(&mut new_iv).map_err(|_| Error::Crypto(CryptoError::Decrypt))?;

        // --- Update outer header in-place ----------------------------
        self.state.outer_header.master_seed = MasterSeed(new_master_seed);
        self.state.outer_header.encryption_iv = EncryptionIv(new_iv);

        match self.version {
            Version::V3 => {
                // KDBX3 keeps the AES-KDF transform seed in the outer
                // header. Refresh it; rounds are unchanged.
                let mut new_transform_seed = [0u8; 32];
                getrandom::fill(&mut new_transform_seed)
                    .map_err(|_| Error::Crypto(CryptoError::Decrypt))?;
                self.state.outer_header.transform_seed = Some(TransformSeed(new_transform_seed));
            }
            Version::V4 => {
                // KDBX4 keeps KDF parameters as a VarDictionary blob.
                // Reparse, replace the `S` value (Argon2 salt or
                // AES-KDF seed — same key in both shapes), reserialise.
                let blob = self
                    .state
                    .outer_header
                    .kdf_parameters
                    .as_ref()
                    .ok_or(Error::Format(FormatError::MalformedHeader(
                        "KDBX4 missing KdfParameters",
                    )))?;
                let mut dict = VarDictionary::parse(blob)
                    .map_err(|_| FormatError::MalformedHeader("malformed KDF parameters"))?;
                let salt_len = match dict.get("S") {
                    Some(VarValue::Bytes(b)) => b.len(),
                    _ => {
                        return Err(Error::Format(FormatError::MalformedHeader(
                            "KDF parameters missing salt/seed key 'S'",
                        )));
                    }
                };
                let mut new_salt = vec![0u8; salt_len];
                getrandom::fill(&mut new_salt).map_err(|_| Error::Crypto(CryptoError::Decrypt))?;
                dict.entries
                    .insert("S".to_owned(), VarValue::Bytes(new_salt));
                let new_blob = dict
                    .write()
                    .map_err(|_| FormatError::MalformedHeader("failed to encode KDF parameters"))?;
                self.state.outer_header.kdf_parameters = Some(new_blob);
            }
        }

        // --- Re-derive the transformed key against the rotated KDF ---
        let kdf_params = self
            .state
            .outer_header
            .decode_kdf_params()
            .map_err(|_| FormatError::MalformedHeader("malformed KDF parameters"))?;
        let new_transformed =
            derive_transformed_key(new_key, &kdf_params).map_err(|_| CryptoError::Kdf)?;
        self.state.transformed_key = new_transformed;

        // --- Bookkeeping ---------------------------------------------
        let now = self.state.clock.now();
        self.state.vault.meta.master_key_changed = Some(now);
        self.state.vault.meta.settings_changed = Some(now);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Vault-tree helpers used by the mutation API.
// ---------------------------------------------------------------------------

/// Read-only sibling of [`find_group_mut`] used by `move_group`'s
/// cycle check, where mutating the source subtree before the check
/// passes would be wrong.
fn find_group(root: &Group, id: GroupId) -> Option<&Group> {
    if root.id == id {
        return Some(root);
    }
    for child in &root.groups {
        if let Some(hit) = find_group(child, id) {
            return Some(hit);
        }
    }
    None
}

/// Whether `target` exists anywhere in the subtree rooted at `root`,
/// including at `root` itself. Used by `move_group` to reject moves
/// that would make a group a descendant of itself.
fn subtree_contains(root: &Group, target: GroupId) -> bool {
    if root.id == target {
        return true;
    }
    root.groups.iter().any(|g| subtree_contains(g, target))
}

/// Remove the group with the given id from wherever it lives in the
/// tree rooted at `root`, returning the removed subtree. Used by
/// `delete_group`. The root group cannot be removed this way — its
/// id check happens before this is called.
fn remove_group_with_parent(root: &mut Group, id: GroupId) -> Option<Group> {
    if let Some(pos) = root.groups.iter().position(|g| g.id == id) {
        return Some(root.groups.remove(pos));
    }
    for child in &mut root.groups {
        if let Some(g) = remove_group_with_parent(child, id) {
            return Some(g);
        }
    }
    None
}

/// Variant of [`remove_group_with_parent`] that also returns the
/// [`GroupId`] of the parent the removed subtree came out of, used by
/// `move_group` to populate `previous_parent_group`.
fn remove_group_with_parent_pair(root: &mut Group, id: GroupId) -> Option<(Group, GroupId)> {
    if let Some(pos) = root.groups.iter().position(|g| g.id == id) {
        return Some((root.groups.remove(pos), root.id));
    }
    for child in &mut root.groups {
        if let Some(pair) = remove_group_with_parent_pair(child, id) {
            return Some(pair);
        }
    }
    None
}

/// Build a [`DeletedObject`] tombstone (stamped `at`) for the group
/// itself plus every entry and every subgroup recursively under it,
/// in depth-first order. Used by `delete_group` so a peer replica
/// merging against this vault can distinguish deleted records from
/// never-seen ones.
fn collect_subtree_tombstones(
    group: &Group,
    at: chrono::DateTime<chrono::Utc>,
) -> Vec<DeletedObject> {
    let mut out = Vec::new();
    push_subtree_tombstones(group, at, &mut out);
    out
}

fn push_subtree_tombstones(
    group: &Group,
    at: chrono::DateTime<chrono::Utc>,
    out: &mut Vec<DeletedObject>,
) {
    for e in &group.entries {
        out.push(DeletedObject {
            uuid: e.id.0,
            deleted_at: Some(at),
        });
    }
    for child in &group.groups {
        push_subtree_tombstones(child, at, out);
    }
    out.push(DeletedObject {
        uuid: group.id.0,
        deleted_at: Some(at),
    });
}

/// Walk the tree rooted at `root` looking for a group with the given id.
/// Returns a mutable reference to the first match, or `None`.
fn find_group_mut(root: &mut Group, id: GroupId) -> Option<&mut Group> {
    if root.id == id {
        return Some(root);
    }
    for child in &mut root.groups {
        if let Some(hit) = find_group_mut(child, id) {
            return Some(hit);
        }
    }
    None
}

/// Remove the entry with the given id from wherever it lives in the
/// tree rooted at `root`. Returns the removed entry paired with the
/// [`GroupId`] of the parent group it came out of, or `None` if no
/// entry with that id exists anywhere in the subtree.
///
/// The parent id is what `move_entry` records in
/// `entry.previous_parent_group` and what `delete_entry` ignores.
fn remove_entry_with_parent(root: &mut Group, id: EntryId) -> Option<(Entry, GroupId)> {
    if let Some(pos) = root.entries.iter().position(|e| e.id == id) {
        return Some((root.entries.remove(pos), root.id));
    }
    for child in &mut root.groups {
        if let Some(pair) = remove_entry_with_parent(child, id) {
            return Some(pair);
        }
    }
    None
}

/// `true` if `candidate` matches any existing entry id, group id, or
/// the root group id. Used by [`Kdbx::add_entry`] to reject
/// caller-supplied UUIDs that would collide.
fn uuid_in_use(vault: &Vault, candidate: uuid::Uuid) -> bool {
    group_uuid_in_use(&vault.root, candidate)
}

fn group_uuid_in_use(group: &Group, candidate: uuid::Uuid) -> bool {
    if group.id.0 == candidate {
        return true;
    }
    // Walk both the live entry ids AND every history snapshot's id.
    // Tree-wide UUID uniqueness on the wire includes history entries
    // — KeePass writers assign history snapshots their own `<UUID>`
    // element, and `import_entry(mint_new_uuid=false)`'s pre-mutation
    // collision check has to catch incoming UUIDs that collide with
    // a pre-existing history id (not just a live one). Also fixes a
    // latent hole on `add_entry`'s caller-supplied-UUID rejection
    // path, which uses the same helper.
    if group
        .entries
        .iter()
        .any(|e| e.id.0 == candidate || e.history.iter().any(|s| s.id.0 == candidate))
    {
        return true;
    }
    group.groups.iter().any(|g| group_uuid_in_use(g, candidate))
}

/// Generate a fresh v4 UUID that doesn't collide with any existing
/// entry or group in the vault. In practice `Uuid::new_v4()` is
/// globally unique and the loop is belt-and-braces, but the loop
/// makes the "never collide" invariant explicit.
fn fresh_uuid(vault: &Vault) -> uuid::Uuid {
    loop {
        let candidate = uuid::Uuid::new_v4();
        if !uuid_in_use(vault, candidate) {
            return candidate;
        }
    }
}

/// Insertion + content-hash dedup core for [`Kdbx::add_custom_icon`].
///
/// Returns `(uuid, inserted)`. When `inserted == true`, a fresh icon
/// was pushed and the caller should stamp
/// [`crate::model::Meta::settings_changed`]; when `false`, dedup hit
/// an existing icon and nothing about the pool has changed (so no
/// stamp).
///
/// Extracted from the public method so a unit test can assert the
/// load-bearing idempotence invariant directly — `name` and
/// `last_modified` on an existing icon must NOT be overwritten by a
/// same-bytes re-insertion. Neither field is on the public surface
/// yet, so crossing the integration-test boundary without an
/// `unsafe` pointer cast or a test-only accessor isn't possible.
fn add_or_dedup_icon(vault: &mut Vault, data: Vec<u8>) -> (uuid::Uuid, bool) {
    let incoming: [u8; 32] = Sha256::digest(&data).into();
    for existing in &vault.meta.custom_icons {
        let hash: [u8; 32] = Sha256::digest(&existing.data).into();
        if hash == incoming {
            return (existing.uuid, false);
        }
    }
    let uuid = fresh_icon_uuid(vault);
    vault.meta.custom_icons.push(CustomIcon {
        uuid,
        data,
        name: String::new(),
        last_modified: None,
    });
    (uuid, true)
}

/// Generate a fresh v4 UUID that doesn't collide with any existing
/// custom-icon UUID in [`Vault::meta::custom_icons`]. Entry/group
/// UUIDs live in a different semantic namespace (the wire format
/// doesn't cross-reference them), but `Uuid::new_v4()` is globally
/// unique anyway; the loop is belt-and-braces.
fn fresh_icon_uuid(vault: &Vault) -> uuid::Uuid {
    loop {
        let candidate = uuid::Uuid::new_v4();
        if !vault.meta.custom_icons.iter().any(|c| c.uuid == candidate) {
            return candidate;
        }
    }
}

/// Apply the attach intents staged inside an `edit_entry` closure to
/// the shared [`Vault::binaries`] pool, then push matching
/// [`Attachment`] references onto the target entry.
///
/// Dedup-by-content-hash: SHA-256 of the payload paired with the
/// `protected` flag is the dedup key. Identical-bytes-but-different-
/// flag attachments stay as separate pool entries because the
/// `protected` flag rides on the binary itself in the KDBX4 inner
/// header (and on the `Protected="True"` `<Value>` attribute on
/// KDBX3); coalescing them would silently flip the flag for one
/// caller.
fn apply_pending_attaches(vault: &mut Vault, id: EntryId, pending: PendingBinaryOps) {
    if pending.attaches.is_empty() {
        return;
    }
    // Index existing pool by (content hash, protected). Take the
    // earliest index on a collision so dedup is deterministic.
    let mut hash_to_idx: HashMap<([u8; 32], bool), u32> = HashMap::new();
    for (i, b) in vault.binaries.iter().enumerate() {
        let h: [u8; 32] = Sha256::digest(&b.data).into();
        hash_to_idx
            .entry((h, b.protected))
            .or_insert_with(|| u32::try_from(i).expect("pool idx fits u32"));
    }

    let mut new_attachments: Vec<Attachment> = Vec::with_capacity(pending.attaches.len());
    for att in pending.attaches {
        let h: [u8; 32] = Sha256::digest(&att.data).into();
        let key = (h, att.protected);
        let ref_id = if let Some(&idx) = hash_to_idx.get(&key) {
            idx
        } else {
            let idx = u32::try_from(vault.binaries.len()).expect("pool idx fits u32");
            vault.binaries.push(Binary {
                data: att.data,
                protected: att.protected,
            });
            hash_to_idx.insert(key, idx);
            idx
        };
        new_attachments.push(Attachment {
            name: att.name,
            ref_id,
        });
    }

    if let Some(e) = find_entry_mut(&mut vault.root, id) {
        e.attachments.extend(new_attachments);
    }
}

/// Refcount-aware garbage collection of [`Vault::binaries`].
///
/// Walks every entry (and every history snapshot) in the vault to
/// build the set of `ref_id`s that are still in use, then drops any
/// pool entry not in that set and renumbers the surviving
/// references so the indexes stay contiguous from 0.
///
/// Called once at the end of `edit_entry` so a `detach` shrinks the
/// pool only when the very last reference (in any entry, this one or
/// another) is gone — a binary shared between two entries survives a
/// detach from one of them.
fn gc_binaries_pool(vault: &mut Vault) {
    let mut in_use: HashSet<u32> = HashSet::new();
    collect_attachment_refs(&vault.root, &mut in_use);

    let n = vault.binaries.len();
    let n_u32 = u32::try_from(n).expect("pool size fits u32");
    if (0..n_u32).all(|i| in_use.contains(&i)) {
        return;
    }

    // Old-index → new-index mapping; `None` for dropped entries.
    let mut remap: Vec<Option<u32>> = Vec::with_capacity(n);
    let mut next: u32 = 0;
    for i in 0..n_u32 {
        if in_use.contains(&i) {
            remap.push(Some(next));
            next += 1;
        } else {
            remap.push(None);
        }
    }

    let kept: Vec<Binary> = vault
        .binaries
        .drain(..)
        .enumerate()
        .filter(|(i, _)| remap[*i].is_some())
        .map(|(_, b)| b)
        .collect();
    vault.binaries = kept;

    renumber_attachments(&mut vault.root, &remap);
}

/// Collect every attachment `ref_id` referenced anywhere under
/// `group`, including inside history snapshots — those are themselves
/// `Entry` values that carry their own attachment lists, and
/// dropping a pool entry a snapshot still references would corrupt
/// the saved file.
fn collect_attachment_refs(group: &Group, out: &mut HashSet<u32>) {
    for e in &group.entries {
        for a in &e.attachments {
            out.insert(a.ref_id);
        }
        for snap in &e.history {
            for a in &snap.attachments {
                out.insert(a.ref_id);
            }
        }
    }
    for child in &group.groups {
        collect_attachment_refs(child, out);
    }
}

/// Save-time refcount GC for [`Vault::meta::custom_icons`].
///
/// Walks every entry (live + every `history[]` snapshot) and every
/// group to collect the set of `custom_icon_uuid` values actually
/// referenced, prunes the pool to that set, and sweeps any surviving
/// reference that no longer resolves (e.g. because the caller ran
/// `remove_custom_icon(X)` without unsetting the field) back to
/// `None`. The on-disk invariant "every `<CustomIconUUID>` resolves
/// in `<CustomIcons>`" is restored before the bytes hit the wire.
///
/// **Rhythm divergence from `gc_binaries_pool`**: the binary-pool
/// GC runs inside every mutation post-pass because attachments can
/// go orphan mid-session and the `Attachment` surface exposes
/// per-entry iteration callers may rely on. Icons neither have a
/// bulk accessor yet nor can they be orphaned by a content edit
/// (only by the explicit `remove_custom_icon`, whose docstring
/// already warns callers), so the icon GC runs only on save. This
/// keeps the hot `edit_entry` path from paying for a tree walk it
/// doesn't need.
fn gc_custom_icons_pool(vault: &mut Vault) {
    let mut in_use: HashSet<uuid::Uuid> = HashSet::new();
    collect_custom_icon_refs(&vault.root, &mut in_use);
    vault.meta.custom_icons.retain(|c| in_use.contains(&c.uuid));

    // Dangling-ref sweep: any entry/group custom_icon_uuid that
    // doesn't resolve in the post-prune pool gets reset to None.
    // Without this the wire format would carry an unresolvable
    // reference.
    let pool: HashSet<uuid::Uuid> = vault.meta.custom_icons.iter().map(|c| c.uuid).collect();
    clear_dangling_custom_icons(&mut vault.root, &pool);
}

/// Collect every `custom_icon_uuid` referenced anywhere under
/// `group`, including inside history snapshots — a snapshot carries
/// its own `custom_icon_uuid` that must keep the referenced icon
/// alive in the pool, same discipline as attachment refs.
fn collect_custom_icon_refs(group: &Group, out: &mut HashSet<uuid::Uuid>) {
    if let Some(u) = group.custom_icon_uuid {
        out.insert(u);
    }
    for e in &group.entries {
        if let Some(u) = e.custom_icon_uuid {
            out.insert(u);
        }
        for snap in &e.history {
            if let Some(u) = snap.custom_icon_uuid {
                out.insert(u);
            }
        }
    }
    for child in &group.groups {
        collect_custom_icon_refs(child, out);
    }
}

/// Walk the tree and reset any `custom_icon_uuid` whose target is no
/// longer in `pool`. Runs after the prune pass in
/// [`gc_custom_icons_pool`].
fn clear_dangling_custom_icons(group: &mut Group, pool: &HashSet<uuid::Uuid>) {
    if let Some(u) = group.custom_icon_uuid {
        if !pool.contains(&u) {
            group.custom_icon_uuid = None;
        }
    }
    for e in &mut group.entries {
        if let Some(u) = e.custom_icon_uuid {
            if !pool.contains(&u) {
                e.custom_icon_uuid = None;
            }
        }
        for snap in &mut e.history {
            if let Some(u) = snap.custom_icon_uuid {
                if !pool.contains(&u) {
                    snap.custom_icon_uuid = None;
                }
            }
        }
    }
    for child in &mut group.groups {
        clear_dangling_custom_icons(child, pool);
    }
}

fn renumber_attachments(group: &mut Group, remap: &[Option<u32>]) {
    for e in &mut group.entries {
        for a in &mut e.attachments {
            if let Some(Some(new)) = remap.get(a.ref_id as usize) {
                a.ref_id = *new;
            }
        }
        for snap in &mut e.history {
            for a in &mut snap.attachments {
                if let Some(Some(new)) = remap.get(a.ref_id as usize) {
                    a.ref_id = *new;
                }
            }
        }
    }
    for child in &mut group.groups {
        renumber_attachments(child, remap);
    }
}

/// Return the [`GroupId`] of the group that directly contains the
/// entry identified by `id`, or `None` if the entry isn't in the
/// tree. Used by the recycle-bin helpers to detect "already inside
/// the bin" via an ancestor walk.
fn entry_parent_group(root: &Group, id: EntryId) -> Option<GroupId> {
    if root.entries.iter().any(|e| e.id == id) {
        return Some(root.id);
    }
    for child in &root.groups {
        if let Some(p) = entry_parent_group(child, id) {
            return Some(p);
        }
    }
    None
}

/// `true` if the group identified by `candidate` is `ancestor`
/// itself OR lives anywhere beneath `ancestor` in the tree rooted
/// at `root`. Used by [`Kdbx::recycle_entry`] /
/// [`Kdbx::recycle_group`] to short-circuit when the target is
/// already inside the recycle bin.
fn group_is_descendant_of(root: &Group, candidate: GroupId, ancestor: GroupId) -> bool {
    if let Some(a) = find_group(root, ancestor) {
        if a.id == candidate {
            return true;
        }
        return group_contains(a, candidate);
    }
    false
}

/// `true` if `group` (or any of its nested subgroups) has id
/// `candidate`.
fn group_contains(group: &Group, candidate: GroupId) -> bool {
    if group.id == candidate {
        return true;
    }
    group.groups.iter().any(|g| group_contains(g, candidate))
}

/// Read-only counterpart to [`find_entry_mut`]. Used by
/// [`Kdbx::export_entry`], which is itself `&self`.
fn find_entry(root: &Group, id: EntryId) -> Option<&Entry> {
    if let Some(e) = root.entries.iter().find(|e| e.id == id) {
        return Some(e);
    }
    for child in &root.groups {
        if let Some(entry) = find_entry(child, id) {
            return Some(entry);
        }
    }
    None
}

/// Append `bin` to [`Vault::binaries`] if no existing binary has
/// identical `(data, protected)`; otherwise return the existing
/// slot's `ref_id`. Used by [`Kdbx::import_entry`] to dedup
/// imported attachment bytes against the destination pool.
///
/// Content-hash comparison uses SHA-256 so a large shared
/// attachment (e.g. a company-logo PNG on many entries) imports
/// exactly once. The `protected` flag is part of the dedup key
/// because the same bytes with a different inner-stream encryption
/// flag are semantically different binaries (the on-disk
/// representation differs).
fn insert_or_dedup_binary(vault: &mut Vault, bin: Binary) -> u32 {
    let incoming: [u8; 32] = Sha256::digest(&bin.data).into();
    for (idx, existing) in vault.binaries.iter().enumerate() {
        if existing.protected == bin.protected {
            let h: [u8; 32] = Sha256::digest(&existing.data).into();
            if h == incoming {
                return u32::try_from(idx).expect("pool index fits u32");
            }
        }
    }
    let new_ref = u32::try_from(vault.binaries.len()).expect("pool index fits u32");
    vault.binaries.push(bin);
    new_ref
}

/// Apply the binary + custom-icon remaps produced during
/// [`Kdbx::import_entry`] to a single [`Entry`]. Walks the entry's
/// attachments and `custom_icon_uuid`; callers invoke this once on
/// the live imported entry and once per history snapshot.
fn remap_entry_refs(
    entry: &mut Entry,
    binary_remap: &HashMap<u32, u32>,
    icon_remap: &HashMap<uuid::Uuid, uuid::Uuid>,
) {
    for a in &mut entry.attachments {
        if let Some(&new) = binary_remap.get(&a.ref_id) {
            a.ref_id = new;
        }
    }
    if let Some(u) = entry.custom_icon_uuid {
        if let Some(&new) = icon_remap.get(&u) {
            entry.custom_icon_uuid = Some(new);
        }
    }
}

/// Locate an entry by id anywhere in the tree rooted at `root`,
/// returning a mutable reference for in-place field edits.
fn find_entry_mut(root: &mut Group, id: EntryId) -> Option<&mut Entry> {
    // Manual loop instead of `iter_mut().find(...)` + recursion:
    // the borrow checker can't prove we don't reborrow through two
    // different subtrees when we use combinators here.
    if let Some(pos) = root.entries.iter().position(|e| e.id == id) {
        return Some(&mut root.entries[pos]);
    }
    for child in &mut root.groups {
        if let Some(entry) = find_entry_mut(child, id) {
            return Some(entry);
        }
    }
    None
}

/// Decide whether a mutation that carries `policy` should push a
/// pre-mutation snapshot given the live entry's current `history` and
/// the current wall-clock `now`.
///
/// Shared by [`Kdbx::edit_entry`] and
/// [`Kdbx::restore_entry_from_history`] — both need the same
/// SnapshotIfOlderThan semantics, and extracting the helper keeps the
/// two call sites from drifting.
fn should_snapshot_now(
    policy: HistoryPolicy,
    history: &[Entry],
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    match policy {
        HistoryPolicy::NoSnapshot => false,
        HistoryPolicy::Snapshot => true,
        HistoryPolicy::SnapshotIfOlderThan(window) => match history.last() {
            None => true,
            Some(last) => {
                let threshold = now - window;
                // Absent timestamp → treat as "ancient" and snapshot.
                last.times
                    .last_modification_time
                    .is_none_or(|t| t < threshold)
            }
        },
    }
}

/// Truncate `history` per `max_items` (negative = unlimited) and
/// `max_size` (negative = unlimited). Oldest entries go first.
///
/// `max_size` is a soft budget measured against an approximation of
/// each entry's serialised XML size: the byte length of the five
/// canonical string fields plus custom fields and tags, plus a
/// 200-byte constant for wrapper markup. Good enough for "don't let
/// a megabyte of history accumulate"; not byte-exact.
fn truncate_history(history: &mut Vec<Entry>, max_items: i32, max_size: i64) {
    // Item-count budget first, since it's cheapest and common.
    if max_items >= 0 {
        let cap = usize::try_from(max_items).unwrap_or(usize::MAX);
        while history.len() > cap {
            history.remove(0);
        }
    }

    // Size budget, if one is declared.
    if max_size >= 0 {
        let cap = u64::try_from(max_size).unwrap_or(u64::MAX);
        let mut total: u64 = history.iter().map(approx_entry_size).sum();
        while total > cap && !history.is_empty() {
            let dropped = approx_entry_size(&history[0]);
            history.remove(0);
            total = total.saturating_sub(dropped);
        }
    }
}

/// Approximate the byte footprint an entry takes up when serialised
/// inside a `<History>` block. Counts the user-visible string bytes
/// plus a constant for XML wrapping overhead.
fn approx_entry_size(e: &Entry) -> u64 {
    let mut n: u64 = 200; // wrapper markup for <Entry>...<History>...</History></Entry>
    n = n.saturating_add(e.title.len() as u64);
    n = n.saturating_add(e.username.len() as u64);
    n = n.saturating_add(e.password.len() as u64);
    n = n.saturating_add(e.url.len() as u64);
    n = n.saturating_add(e.notes.len() as u64);
    for cf in &e.custom_fields {
        n = n.saturating_add(cf.key.len() as u64);
        n = n.saturating_add(cf.value.len() as u64);
    }
    for t in &e.tags {
        n = n.saturating_add(t.len() as u64);
    }
    n
}

// ---------------------------------------------------------------------------
// Unlock pipeline — all the crypto wiring lives here, off the public impl.
// ---------------------------------------------------------------------------

// The pipeline is intentionally a single linear function: breaking it up by
// version or stage tends to spread error-handling across helpers that each
// know only a slice of the context, which makes error-collapse discipline
// harder to audit than a single straight-line function with clearly labelled
// sections.
#[allow(clippy::too_many_lines)]
fn do_unlock(
    bytes: &[u8],
    header_state: &HeaderRead,
    composite: &CompositeKey,
) -> Result<Unlocked, Error> {
    let header = &header_state.header;

    // Twofish-CBC is deliberately deferred — no fixture in the current
    // corpus uses it and the RustCrypto ecosystem's Twofish crate is less
    // audited than AES / ChaCha20. AES-256-CBC and ChaCha20 cover every
    // modern KDBX writer.
    let outer_cipher = match header.cipher_id.well_known() {
        Some(c @ (KnownCipher::Aes256Cbc | KnownCipher::ChaCha20)) => c,
        Some(KnownCipher::TwofishCbc) => {
            return Err(Error::Format(FormatError::MalformedHeader(
                "outer cipher Twofish-CBC is not yet supported",
            )));
        }
        None => {
            return Err(Error::Format(FormatError::MalformedHeader(
                "unrecognised outer cipher UUID",
            )));
        }
    };

    // --- KDF → transformed key → cipher key -------------------------------
    let kdf_params = header
        .decode_kdf_params()
        .map_err(|_| FormatError::MalformedHeader("malformed KDF parameters"))?;
    let transformed =
        derive_transformed_key(composite, &kdf_params).map_err(|_| CryptoError::Kdf)?;
    let cipher_key = derive_cipher_key(&header.master_seed, &transformed);

    // --- Assemble ciphertext + verify integrity ---------------------------
    let header_bytes = &bytes[..header_state.header_end];
    let payload = &bytes[header_state.header_end..];

    let ciphertext: Vec<u8> = match header.version {
        Version::V4 => {
            // Layout: [32-byte header SHA-256][32-byte header HMAC][HMAC blocks].
            if payload.len() < 64 {
                return Err(FormatError::Truncated {
                    needed: 64,
                    got: payload.len(),
                }
                .into());
            }
            let (header_hash, rest) = payload.split_at(32);
            let (header_hmac, blocks) = rest.split_at(32);

            let hmac_base = derive_hmac_base_key(&header.master_seed, &transformed);
            verify_header_hash(
                header_bytes,
                header_hash.try_into().expect("split_at guarantees 32"),
            )
            .map_err(|_| CryptoError::Decrypt)?;
            verify_header_hmac(
                header_bytes,
                header_hmac.try_into().expect("split_at guarantees 32"),
                &hmac_base,
            )
            .map_err(|_| CryptoError::Decrypt)?;

            read_hmac_block_stream(blocks, &hmac_base).map_err(FormatError::from)?
        }
        Version::V3 => payload.to_vec(),
    };

    // --- Outer-cipher decrypt ---------------------------------------------
    let plaintext = match outer_cipher {
        KnownCipher::Aes256Cbc => {
            aes_256_cbc_decrypt(&cipher_key, &header.encryption_iv, &ciphertext)
                .map_err(|_| CryptoError::Decrypt)?
        }
        KnownCipher::ChaCha20 => chacha20_decrypt(&cipher_key, &header.encryption_iv, &ciphertext)
            .map_err(|_| CryptoError::Decrypt)?,
        KnownCipher::TwofishCbc => unreachable!("rejected above"),
    };

    // --- Version-specific plaintext framing --------------------------------
    // KDBX4 binaries come out of the inner header (decrypted + populated
    // into the local `binaries` Vec below, then assigned to
    // `vault.binaries` in the V4 arm). KDBX3 binaries come out of
    // `<Meta><Binaries>` and are populated directly onto `vault.binaries`
    // by `decode_vault_with_cipher` — the V3 arm leaves the local empty.
    let mut binaries: Vec<Binary> = Vec::new();
    let (xml_bytes, inner_stream_algorithm, inner_stream_key): (Vec<u8>, _, Vec<u8>) =
        match header.version {
            Version::V3 => {
                let sentinel =
                    header
                        .stream_start_bytes
                        .as_ref()
                        .ok_or(FormatError::MalformedHeader(
                            "KDBX3 missing StreamStartBytes",
                        ))?;
                if plaintext.len() < 32 {
                    return Err(CryptoError::Decrypt.into());
                }
                let (got_sentinel, rest) = plaintext.split_at(32);
                // Constant-time compare avoids leaking the "password correct,
                // but ciphertext after this point is garbled" partial oracle.
                if got_sentinel.ct_eq(&sentinel.0).unwrap_u8() == 0 {
                    return Err(CryptoError::Decrypt.into());
                }
                let framed = read_hashed_block_stream(rest).map_err(FormatError::from)?;
                let decompressed = decompress(header.compression, &framed)
                    .map_err(|_| FormatError::MalformedHeader("payload failed to decompress"))?;
                let algo = header
                    .inner_stream_algorithm
                    .ok_or(FormatError::MalformedHeader(
                        "KDBX3 missing InnerRandomStreamID",
                    ))?;
                let raw = &header
                    .protected_stream_key
                    .as_ref()
                    .ok_or(FormatError::MalformedHeader(
                        "KDBX3 missing ProtectedStreamKey",
                    ))?
                    .0;
                // KDBX3 quirk: the inner-stream key on disk is hashed with
                // SHA-256 before it becomes the Salsa20 key. KDBX4 skips
                // this step (ChaCha20's SHA-512 derivation in
                // InnerStreamCipher::new does the equivalent internally).
                let hashed = Sha256::digest(raw);
                (decompressed, algo, hashed.to_vec())
            }
            Version::V4 => {
                let decompressed = decompress(header.compression, &plaintext)
                    .map_err(|_| FormatError::MalformedHeader("payload failed to decompress"))?;
                let inner = InnerHeader::parse(&decompressed)
                    .map_err(|_| FormatError::MalformedHeader("malformed inner header"))?;
                let xml = decompressed[inner.consumed_bytes..].to_vec();
                // Inner-stream cipher is shared between inner-header
                // binaries and XML protected values: binaries consume
                // keystream first (in inner-header order), then XML
                // values pick up where they left off. We build the
                // cipher here so that we can pre-decrypt the protected
                // binaries, then hand the (advanced) cipher on to the
                // XML decoder.
                let mut c =
                    InnerStreamCipher::new(inner.inner_stream_algorithm, &inner.inner_stream_key)
                        .map_err(|_| CryptoError::Decrypt)?;
                for inner_bin in inner.binaries {
                    let protected = inner_bin.is_protected();
                    let mut data = inner_bin.data;
                    if protected {
                        c.process(&mut data);
                    }
                    binaries.push(Binary { data, protected });
                }
                let mut vault = decode_vault_with_cipher(&xml, &mut c)?;
                vault.binaries = binaries;
                return Ok(Unlocked {
                    vault,
                    outer_header: header.clone(),
                    inner_stream: Some(InnerStreamParams {
                        algorithm: inner.inner_stream_algorithm,
                        key: inner.inner_stream_key,
                    }),
                    transformed_key: transformed,
                    clock: Box::new(SystemClock),
                });
            }
        };

    // --- Inner-stream cipher + XML decode (KDBX3) --------------------------
    let mut cipher = InnerStreamCipher::new(inner_stream_algorithm, &inner_stream_key)
        .map_err(|_| CryptoError::Decrypt)?;
    let vault = decode_vault_with_cipher(&xml_bytes, &mut cipher)?;
    // `vault.binaries` is already populated from `<Meta><Binaries>` by the
    // decoder. The KDBX4 arm above assigned the inner-header binaries to
    // its own short-circuited return; on this V3 path the local `binaries`
    // is empty and there is nothing to assign.
    Ok(Unlocked {
        vault,
        outer_header: header.clone(),
        // KDBX3 uses outer-header fields, but the *effective* inner-stream
        // key is SHA-256(ProtectedStreamKey). Cache the hashed form so
        // save_to_bytes can spin up a fresh cipher symmetrically with
        // how the decoder built one.
        inner_stream: Some(InnerStreamParams {
            algorithm: inner_stream_algorithm,
            key: inner_stream_key,
        }),
        transformed_key: transformed,
        clock: Box::new(SystemClock),
    })
}

// ---------------------------------------------------------------------------
// Save pipeline — the byte-level inverse of do_unlock.
// ---------------------------------------------------------------------------

fn do_save(signature: FileSignature, version: Version, state: &Unlocked) -> Result<Vec<u8>, Error> {
    // Save-time GC mutates a local clone of the vault so the
    // caller-visible in-memory state stays byte-stable across a
    // save. See `gc_custom_icons_pool` for the rhythm divergence
    // from the binary-pool GC (which runs on every mutation).
    let mut vault = state.vault.clone();
    gc_custom_icons_pool(&mut vault);
    match version {
        Version::V3 => do_save_v3(signature, state, &vault),
        Version::V4 => do_save_v4(signature, state, &vault),
    }
}

fn do_save_v4(signature: FileSignature, state: &Unlocked, vault: &Vault) -> Result<Vec<u8>, Error> {
    let header = &state.outer_header;
    let inner_params = state
        .inner_stream
        .as_ref()
        .ok_or(FormatError::MalformedHeader(
            "KDBX4 save_to_bytes requires inner-stream parameters from unlock",
        ))?;

    // AES-256-CBC and ChaCha20 are wired up for writes; Twofish-CBC is
    // still deferred, matching the decrypt side.
    let outer_cipher = match header.cipher_id.well_known() {
        Some(c @ (KnownCipher::Aes256Cbc | KnownCipher::ChaCha20)) => c,
        Some(KnownCipher::TwofishCbc) => {
            return Err(Error::Format(FormatError::MalformedHeader(
                "KDBX4 save_to_bytes does not support Twofish-CBC",
            )));
        }
        None => {
            return Err(Error::Format(FormatError::MalformedHeader(
                "KDBX4 save_to_bytes: unrecognised outer cipher",
            )));
        }
    };

    // --- Inner-stream cipher + inner header binaries ---------------------
    let mut inner_cipher = InnerStreamCipher::new(inner_params.algorithm, &inner_params.key)
        .map_err(|_| CryptoError::Decrypt)?;

    // `vault` comes from `do_save` post-GC — see the clone-and-prune
    // comment there. `state.vault` stays untouched.
    let mut inner_binaries: Vec<InnerBinary> = Vec::with_capacity(vault.binaries.len());
    for b in &vault.binaries {
        let flags: u8 = u8::from(b.protected);
        let mut data = b.data.clone();
        if b.protected {
            // Stream cipher: XOR in the same keystream direction to
            // re-encrypt. The cipher advances by `data.len()` bytes.
            inner_cipher.process(&mut data);
        }
        inner_binaries.push(InnerBinary { flags, data });
    }

    let inner_header = InnerHeader {
        inner_stream_algorithm: inner_params.algorithm,
        inner_stream_key: inner_params.key.clone(),
        binaries: inner_binaries,
        consumed_bytes: 0, // unused by write()
    };
    let inner_header_bytes = inner_header
        .write()
        .map_err(|_| FormatError::MalformedHeader("failed to write inner header"))?;

    // --- XML encode with the same cipher (now advanced past binaries) ----
    let xml_bytes = encode_vault_with_cipher(vault, &mut inner_cipher)?;

    // --- Decompressed plaintext = inner header || XML --------------------
    let mut decompressed = Vec::with_capacity(inner_header_bytes.len() + xml_bytes.len());
    decompressed.extend_from_slice(&inner_header_bytes);
    decompressed.extend_from_slice(&xml_bytes);

    // --- Compress if declared --------------------------------------------
    let plaintext = compress(header.compression, &decompressed)
        .map_err(|_| FormatError::MalformedHeader("compression failed on write"))?;

    // --- Derive cipher key + HMAC base key from the cached transformed key
    let cipher_key = derive_cipher_key(&header.master_seed, &state.transformed_key);
    let hmac_base = derive_hmac_base_key(&header.master_seed, &state.transformed_key);

    // --- Outer-cipher encrypt --------------------------------------------
    let ciphertext = match outer_cipher {
        KnownCipher::Aes256Cbc => {
            aes_256_cbc_encrypt(&cipher_key, &header.encryption_iv, &plaintext)
                .map_err(|_| CryptoError::Decrypt)?
        }
        KnownCipher::ChaCha20 => chacha20_encrypt(&cipher_key, &header.encryption_iv, &plaintext)
            .map_err(|_| CryptoError::Decrypt)?,
        KnownCipher::TwofishCbc => unreachable!("rejected above"),
    };

    // --- Build outer header bytes (signature + TLVs) ---------------------
    let mut header_bytes = Vec::with_capacity(256);
    header_bytes.extend_from_slice(&SIGNATURE_1);
    header_bytes.extend_from_slice(&SIGNATURE_2);
    header_bytes.extend_from_slice(&signature.minor.to_le_bytes());
    header_bytes.extend_from_slice(&signature.major.to_le_bytes());
    let tlv_bytes = header
        .write()
        .map_err(|_| FormatError::MalformedHeader("failed to write outer header"))?;
    header_bytes.extend_from_slice(&tlv_bytes);

    // --- Header hash + HMAC + HMAC block stream of ciphertext ------------
    let header_hash = compute_header_hash(&header_bytes);
    let header_hmac = compute_header_hmac(&header_bytes, &hmac_base);
    let block_stream = write_hmac_block_stream(&ciphertext, &hmac_base, HMAC_BLOCK_DEFAULT_SIZE)
        .map_err(FormatError::from)?;

    // --- Final assembly --------------------------------------------------
    let mut out = Vec::with_capacity(header_bytes.len() + 64 + block_stream.len());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&header_hash);
    out.extend_from_slice(&header_hmac);
    out.extend_from_slice(&block_stream);
    Ok(out)
}

fn do_save_v3(signature: FileSignature, state: &Unlocked, vault: &Vault) -> Result<Vec<u8>, Error> {
    let header = &state.outer_header;
    let inner_params = state
        .inner_stream
        .as_ref()
        .ok_or(FormatError::MalformedHeader(
            "KDBX3 save_to_bytes requires inner-stream parameters from unlock",
        ))?;

    // KDBX3 supports only AES-256-CBC in the shipped reader (ChaCha20 is
    // a KDBX4-only cipher, and Twofish-CBC is still deferred on both).
    match header.cipher_id.well_known() {
        Some(KnownCipher::Aes256Cbc) => {}
        Some(KnownCipher::ChaCha20) => {
            return Err(Error::Format(FormatError::MalformedHeader(
                "KDBX3 save_to_bytes: ChaCha20 is a KDBX4-only cipher",
            )));
        }
        Some(KnownCipher::TwofishCbc) => {
            return Err(Error::Format(FormatError::MalformedHeader(
                "KDBX3 save_to_bytes does not support Twofish-CBC",
            )));
        }
        None => {
            return Err(Error::Format(FormatError::MalformedHeader(
                "KDBX3 save_to_bytes: unrecognised outer cipher",
            )));
        }
    }

    let stream_start_bytes =
        header
            .stream_start_bytes
            .as_ref()
            .ok_or(FormatError::MalformedHeader(
                "KDBX3 save_to_bytes requires StreamStartBytes in the outer header",
            ))?;

    // --- Build outer header bytes (signature + TLVs) ---------------------
    // We compute these *before* the XML encode so the SHA-256 of the
    // header bytes can be threaded into `<Meta><HeaderHash>` per the
    // KeePass V3 spec. None of the header TLVs depend on XML content,
    // so the order swap is safe.
    let mut header_bytes = Vec::with_capacity(256);
    header_bytes.extend_from_slice(&SIGNATURE_1);
    header_bytes.extend_from_slice(&SIGNATURE_2);
    header_bytes.extend_from_slice(&signature.minor.to_le_bytes());
    header_bytes.extend_from_slice(&signature.major.to_le_bytes());
    let tlv_bytes = header
        .write()
        .map_err(|_| FormatError::MalformedHeader("failed to write outer header"))?;
    header_bytes.extend_from_slice(&tlv_bytes);
    let header_hash_b64 = BASE64.encode(compute_header_hash(&header_bytes));

    // --- Inner-stream cipher + XML encode --------------------------------
    // KDBX3 has no inner header and no inner-header binaries pool — any
    // attachment bytes live inside the XML's <Binaries> section. The
    // inner-stream cipher only touches protected <Value> elements; the
    // KDBX3-shaped encoder also emits the <Meta><Binaries> pool from
    // `vault.binaries`, so attachments survive the round-trip.
    let mut inner_cipher = InnerStreamCipher::new(inner_params.algorithm, &inner_params.key)
        .map_err(|_| CryptoError::Decrypt)?;
    let xml_bytes =
        encode_vault_kdbx3_with_cipher_and_header_hash(vault, &mut inner_cipher, &header_hash_b64)?;

    // --- Compress XML (if declared) --------------------------------------
    let compressed = compress(header.compression, &xml_bytes)
        .map_err(|_| FormatError::MalformedHeader("compression failed on write"))?;

    // --- Wrap in a HashedBlockStream -------------------------------------
    let framed = write_hashed_block_stream(&compressed, HASHED_BLOCK_DEFAULT_SIZE)
        .map_err(FormatError::from)?;

    // --- Prepend the stream-start sentinel -------------------------------
    let mut plaintext = Vec::with_capacity(32 + framed.len());
    plaintext.extend_from_slice(&stream_start_bytes.0);
    plaintext.extend_from_slice(&framed);

    // --- Outer-cipher encrypt --------------------------------------------
    let cipher_key = derive_cipher_key(&header.master_seed, &state.transformed_key);
    let ciphertext = aes_256_cbc_encrypt(&cipher_key, &header.encryption_iv, &plaintext)
        .map_err(|_| CryptoError::Decrypt)?;

    // KDBX3 has no header HMAC — the encrypted StreamStartBytes
    // sentinel is the integrity check. Just append the ciphertext to
    // the header bytes we built up front.
    let mut out = Vec::with_capacity(header_bytes.len() + ciphertext.len());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal "just signature, no header fields" byte sequence that
    /// is enough to pass [`Kdbx::open_from_bytes`] but would fail
    /// `read_header` (no end-of-header sentinel).
    fn signature_only(major: u16, minor: u16) -> Vec<u8> {
        use crate::format::{SIGNATURE_1, SIGNATURE_2};
        let mut v = Vec::with_capacity(12);
        v.extend_from_slice(&SIGNATURE_1);
        v.extend_from_slice(&SIGNATURE_2);
        v.extend_from_slice(&minor.to_le_bytes());
        v.extend_from_slice(&major.to_le_bytes());
        v
    }

    #[test]
    fn open_from_bytes_accepts_valid_signature() {
        let bytes = signature_only(4, 1);
        let kdbx = Kdbx::<Sealed>::open_from_bytes(bytes).unwrap();
        assert_eq!(kdbx.version(), Version::V4);
        assert_eq!(kdbx.signature().major, 4);
        assert_eq!(kdbx.signature().minor, 1);
    }

    #[test]
    fn open_from_bytes_rejects_bad_magic() {
        let bytes = vec![0u8; 12];
        let err = Kdbx::<Sealed>::open_from_bytes(bytes).unwrap_err();
        assert!(matches!(
            err,
            Error::Format(crate::format::FormatError::BadSignature1)
        ));
    }

    #[test]
    fn open_from_bytes_rejects_unsupported_major() {
        let bytes = signature_only(99, 0);
        let err = Kdbx::<Sealed>::open_from_bytes(bytes).unwrap_err();
        assert!(matches!(
            err,
            Error::Format(crate::format::FormatError::UnsupportedVersion { major: 99, .. })
        ));
    }

    #[test]
    fn open_from_bytes_rejects_truncated_file() {
        let bytes = vec![0x03, 0xD9, 0xA2];
        let err = Kdbx::<Sealed>::open_from_bytes(bytes).unwrap_err();
        assert!(matches!(
            err,
            Error::Format(crate::format::FormatError::Truncated { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // ChaCha20 save round-trip (synthetic)
    //
    // No fixture in the current corpus emits a ChaCha20 outer cipher, so the
    // end-to-end save path for ChaCha20 cannot be exercised by the standard
    // fixture round-trip test. Instead we: unlock an AES-256-CBC fixture,
    // rewrite its outer header's cipher_id + encryption_iv to ChaCha20 shape,
    // save_to_bytes, re-open with the same composite key, and assert the
    // round-tripped vault equals the original. The test has crate-private
    // access to the `Unlocked` state and so can mutate the retained outer
    // header directly.
    // -----------------------------------------------------------------------

    #[test]
    fn chacha20_save_round_trips_on_synthetic_reconfiguration() {
        use std::{fs, path::Path};

        use crate::CompositeKey;
        use crate::format::{CipherId, EncryptionIv};
        use uuid::Uuid;

        // Anchor the fixture path relative to this crate.
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/fixtures/kdbxweb/kdbx4-basic.kdbx");
        assert!(fixture.exists(), "fixture missing: {fixture:?}");

        // Sidecar password.
        let sidecar_path = fixture.with_extension("json");
        let sidecar_text = fs::read_to_string(&sidecar_path).unwrap();
        // Minimal parse: find "master_password": "...".
        let password = sidecar_text
            .split("\"master_password\"")
            .nth(1)
            .and_then(|s| s.split('"').nth(1))
            .unwrap()
            .to_owned();
        let composite = CompositeKey::from_password(password.as_bytes());

        // Leg 1: unlock.
        let bytes = fs::read(&fixture).unwrap();
        let unlocked = Kdbx::<Sealed>::open_from_bytes(bytes)
            .unwrap()
            .read_header()
            .unwrap()
            .unlock(&composite)
            .unwrap();
        let vault_before = unlocked.vault().clone();

        // Mutate cipher_id and encryption_iv to ChaCha20 shape. The IV is
        // deterministic garbage for reproducibility; ChaCha20 accepts any
        // 12-byte nonce.
        let mut patched = unlocked;
        patched.state.outer_header.cipher_id = CipherId(Uuid::from_bytes([
            0xd6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c, 0xb5, 0xa5, 0x24, 0x33, 0x9a, 0x31, 0xdb,
            0xb5, 0x9a,
        ]));
        patched.state.outer_header.encryption_iv = EncryptionIv(vec![0x77u8; 12]);

        // Save.
        let saved = patched.save_to_bytes().expect("save with ChaCha20 cipher");

        // Leg 2: re-open and unlock.
        let reopened = Kdbx::<Sealed>::open_from_bytes(saved)
            .unwrap()
            .read_header()
            .unwrap()
            .unlock(&composite)
            .unwrap();
        let vault_after = reopened.vault();

        // Compare the encoder-covered subset.
        assert_eq!(vault_before.meta.generator, vault_after.meta.generator);
        assert_eq!(
            vault_before.meta.database_name,
            vault_after.meta.database_name
        );
        assert_eq!(vault_before.total_entries(), vault_after.total_entries());
        for (a, b) in vault_before.iter_entries().zip(vault_after.iter_entries()) {
            assert_eq!(a.title, b.title);
            assert_eq!(a.username, b.username);
            assert_eq!(a.password, b.password);
            assert_eq!(a.url, b.url);
        }
    }

    // -----------------------------------------------------------------
    // add_or_dedup_icon — pure-helper idempotence invariant
    // -----------------------------------------------------------------

    fn empty_vault() -> Vault {
        use crate::model::{Group, GroupId, Meta};
        Vault {
            root: Group {
                id: GroupId(uuid::Uuid::nil()),
                name: String::new(),
                notes: String::new(),
                groups: Vec::new(),
                entries: Vec::new(),
                is_expanded: true,
                default_auto_type_sequence: String::new(),
                enable_auto_type: None,
                enable_searching: None,
                custom_data: Vec::new(),
                previous_parent_group: None,
                last_top_visible_entry: None,
                custom_icon_uuid: None,
                icon_id: 0,
                times: Timestamps::default(),
                unknown_xml: Vec::new(),
            },
            meta: Meta::default(),
            binaries: Vec::new(),
            deleted_objects: Vec::new(),
        }
    }

    #[test]
    fn add_or_dedup_icon_dedup_preserves_existing_metadata() {
        // First insert establishes the icon, then we hand-label it
        // to simulate a caller that has previously named it. A
        // second insert with the same bytes must dedup back to the
        // same UUID AND leave `name` / `last_modified` alone —
        // otherwise any Keys "re-register this icon" flow would
        // silently wipe user-set labels.
        let mut vault = empty_vault();
        let (first, inserted) = add_or_dedup_icon(&mut vault, b"icon-bytes".to_vec());
        assert!(inserted);
        vault.meta.custom_icons[0].name = "My Label".to_owned();
        let marker_ts: chrono::DateTime<chrono::Utc> = "2024-05-06T07:08:09Z".parse().unwrap();
        vault.meta.custom_icons[0].last_modified = Some(marker_ts);

        let (second, inserted) = add_or_dedup_icon(&mut vault, b"icon-bytes".to_vec());
        assert_eq!(first, second, "dedup returns the existing UUID");
        assert!(!inserted, "dedup must not stamp settings_changed");
        assert_eq!(vault.meta.custom_icons.len(), 1);
        assert_eq!(vault.meta.custom_icons[0].name, "My Label");
        assert_eq!(vault.meta.custom_icons[0].last_modified, Some(marker_ts));
    }

    #[test]
    fn add_or_dedup_icon_different_bytes_mint_new_entry() {
        let mut vault = empty_vault();
        let (a, inserted_a) = add_or_dedup_icon(&mut vault, b"first".to_vec());
        let (b, inserted_b) = add_or_dedup_icon(&mut vault, b"second".to_vec());
        assert!(inserted_a && inserted_b);
        assert_ne!(a, b);
        assert_eq!(vault.meta.custom_icons.len(), 2);
    }

    #[test]
    fn replace_vault_swaps_in_replacement_and_subsequent_edits_work() {
        use std::{fs, path::Path};

        use crate::CompositeKey;
        use crate::model::NewEntry;

        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/fixtures/kdbxweb/kdbx4-basic.kdbx");
        let sidecar_text = fs::read_to_string(fixture.with_extension("json")).unwrap();
        let password = sidecar_text
            .split("\"master_password\"")
            .nth(1)
            .and_then(|s| s.split('"').nth(1))
            .unwrap()
            .to_owned();
        let composite = CompositeKey::from_password(password.as_bytes());
        let bytes = fs::read(&fixture).unwrap();
        let mut unlocked = Kdbx::<Sealed>::open_from_bytes(bytes)
            .unwrap()
            .read_header()
            .unwrap()
            .unlock(&composite)
            .unwrap();

        // Build a replacement vault by cloning the current one and tagging
        // the database name so we can prove the swap landed.
        let mut replacement = unlocked.vault().clone();
        replacement.meta.database_name = "replaced".to_owned();
        let original_root_id = replacement.root.id;

        unlocked.replace_vault(replacement);
        assert_eq!(unlocked.vault().meta.database_name, "replaced");

        // Subsequent editor methods continue to work against the new vault —
        // proves the swap doesn't break internal state. add_entry needs a
        // valid parent group, which the cloned vault carries unchanged.
        let new_id = unlocked
            .add_entry(original_root_id, NewEntry::new("post-swap entry"))
            .expect("add_entry post-replace");
        assert!(unlocked.vault().root.entries.iter().any(|e| e.id == new_id));
    }
}
