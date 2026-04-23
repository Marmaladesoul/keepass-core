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
//!   into the [`crate::model::Vault`] tree. Read operations are available;
//!   write-back lands in a follow-up.

use std::fs;
use std::marker::PhantomData;
use std::path::Path;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::crypto::{
    CryptoError, InnerStreamCipher, aes_256_cbc_decrypt, aes_256_cbc_encrypt, chacha20_decrypt,
    chacha20_encrypt, compress, decompress, derive_cipher_key, derive_hmac_base_key,
    derive_transformed_key,
};
use crate::error::Error;
use crate::format::{
    FileSignature, FormatError, HASHED_BLOCK_DEFAULT_SIZE, HMAC_BLOCK_DEFAULT_SIZE, InnerBinary,
    InnerHeader, InnerStreamAlgorithm, KnownCipher, OuterHeader, SIGNATURE_1, SIGNATURE_2, Version,
    compute_header_hash, compute_header_hmac, read_hashed_block_stream, read_header_fields,
    read_hmac_block_stream, verify_header_hash, verify_header_hmac, write_hashed_block_stream,
    write_hmac_block_stream,
};
use crate::model::{
    AutoType, Binary, Clock, DeletedObject, Entry, EntryId, Group, GroupId, ModelError, NewEntry,
    SystemClock, Timestamps, Vault,
};
use crate::secret::{CompositeKey, TransformedKey};
use crate::xml::{decode_vault_with_cipher, encode_vault_with_cipher};

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
    /// KDBX4 only: the inner-stream cipher's algorithm and key, retained
    /// so `save_to_bytes` can spin up a fresh [`InnerStreamCipher`] that
    /// encrypts protected values symmetrically with how they were
    /// decrypted on unlock. On KDBX3 the equivalent lives in the outer
    /// header, and save_to_bytes is not yet implemented for KDBX3.
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
// HeaderRead: accessors; unlock lands in a follow-up
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

    /// Mutable access to the decoded vault — for in-place edits before
    /// a save.
    pub fn vault_mut(&mut self) -> &mut Vault {
        &mut self.state.vault
    }

    /// The [`Clock`] this unlocked database uses to stamp timestamps
    /// during mutations. Either [`SystemClock`] (default, from
    /// [`Kdbx::<HeaderRead>::unlock`]) or whatever was passed to
    /// [`Kdbx::<HeaderRead>::unlock_with_clock`].
    #[must_use]
    pub fn clock(&self) -> &dyn Clock {
        &*self.state.clock
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
        let removed =
            remove_entry(&mut self.state.vault.root, id).ok_or(ModelError::EntryNotFound(id))?;
        let now = self.state.clock.now();
        self.state.vault.deleted_objects.push(DeletedObject {
            uuid: removed.id.0,
            deleted_at: Some(now),
        });
        Ok(())
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
    /// This first implementation targets **KDBX4 with AES-256-CBC**,
    /// which is the default emitted by KeePassXC and covers the bulk
    /// of real-world vaults. Other configurations return
    /// [`FormatError::MalformedHeader`] with a description of what's
    /// not yet supported:
    ///
    /// - KDBX3 (the signature + outer header is emitted but the
    ///   HashedBlockStream writer and the different inner-stream key
    ///   path aren't wired up yet).
    /// - ChaCha20 outer cipher.
    /// - Twofish-CBC outer cipher (which `unlock` already rejects).
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
}

// ---------------------------------------------------------------------------
// Vault-tree helpers used by the mutation API.
// ---------------------------------------------------------------------------

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
/// tree rooted at `root`. Returns the removed entry, or `None` if no
/// entry with that id exists anywhere in the subtree.
fn remove_entry(root: &mut Group, id: EntryId) -> Option<Entry> {
    if let Some(pos) = root.entries.iter().position(|e| e.id == id) {
        return Some(root.entries.remove(pos));
    }
    for child in &mut root.groups {
        if let Some(entry) = remove_entry(child, id) {
            return Some(entry);
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
    if group.entries.iter().any(|e| e.id.0 == candidate) {
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
    // Binaries come out of the KDBX4 inner header. KDBX3 stores them
    // under Meta/Binaries which this pipeline does not yet read, so
    // the pool is empty there.
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
    let mut vault = decode_vault_with_cipher(&xml_bytes, &mut cipher)?;
    vault.binaries = binaries;
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
    match version {
        Version::V3 => do_save_v3(signature, state),
        Version::V4 => do_save_v4(signature, state),
    }
}

fn do_save_v4(signature: FileSignature, state: &Unlocked) -> Result<Vec<u8>, Error> {
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

    let vault = &state.vault;
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

fn do_save_v3(signature: FileSignature, state: &Unlocked) -> Result<Vec<u8>, Error> {
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

    // --- Inner-stream cipher + XML encode --------------------------------
    // KDBX3 has no inner header and no inner-header binaries pool — any
    // attachment bytes live inside the XML's <Binaries> section. The
    // inner-stream cipher only touches protected <Value> elements.
    let mut inner_cipher = InnerStreamCipher::new(inner_params.algorithm, &inner_params.key)
        .map_err(|_| CryptoError::Decrypt)?;
    let xml_bytes = encode_vault_with_cipher(&state.vault, &mut inner_cipher)?;

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

    // --- Build outer header bytes (signature + TLVs) ---------------------
    let mut out = Vec::with_capacity(256 + ciphertext.len());
    out.extend_from_slice(&SIGNATURE_1);
    out.extend_from_slice(&SIGNATURE_2);
    out.extend_from_slice(&signature.minor.to_le_bytes());
    out.extend_from_slice(&signature.major.to_le_bytes());
    let tlv_bytes = header
        .write()
        .map_err(|_| FormatError::MalformedHeader("failed to write outer header"))?;
    out.extend_from_slice(&tlv_bytes);

    // KDBX3 has no header hash or HMAC — the encrypted StreamStartBytes
    // sentinel is the integrity check. Just append the ciphertext.
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
}
