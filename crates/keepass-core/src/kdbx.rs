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

use std::collections::HashMap;
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
    Argon2Variant, Argon2Version, CipherId, CompressionFlags, EncryptionIv, FileSignature,
    FormatError, HASHED_BLOCK_DEFAULT_SIZE, HMAC_BLOCK_DEFAULT_SIZE, InnerBinary, InnerHeader,
    InnerStreamAlgorithm, KdfParams, KnownCipher, MasterSeed, OuterHeader, SIGNATURE_1,
    SIGNATURE_2, TransformSeed, VarDictionary, VarValue, Version, VersionFields,
    compute_header_hash, compute_header_hmac, read_hashed_block_stream, read_header_fields,
    read_hmac_block_stream, verify_header_hash, verify_header_hmac, write_hashed_block_stream,
    write_hmac_block_stream,
};
use crate::model::{
    Binary, Clock, Entry, EntryEditor, EntryId, GroupEditor, GroupId, HistoryPolicy, ModelError,
    NewEntry, NewGroup, PortableEntry, RandomUuids, SystemClock, UuidSource, Vault,
};
use crate::protector::{FieldProtector, ProtectorError, SessionKey, open_with_key, seal_with_key};
use crate::secret::{CompositeKey, TransformedKey};
use crate::xml::{
    decode_vault_with_cipher, encode_vault_kdbx3_with_cipher_and_header_hash,
    encode_vault_with_cipher,
};
use std::sync::Arc;
use zeroize::ZeroizeOnDrop;

use crate::vault_ops;

// The policy / CRUD helpers and verbs now live in `crate::vault_ops` (see
// that module for the seam). The crypto and still-in-place CRUD code below
// calls the pure helpers unqualified, so re-export them at this module's
// root — the compiler enforces that the set is complete.
pub(crate) use crate::vault_ops::binaries::{
    apply_pending_attaches, gc_binaries_pool, insert_or_dedup_binary,
};
pub(crate) use crate::vault_ops::history::{should_snapshot_now, truncate_history};
pub(crate) use crate::vault_ops::icons::gc_custom_icons_pool;
pub(crate) use crate::vault_ops::ids::{fresh_uuid, uuid_in_use};

// Path-preserving re-export: `compute_history_drop_count` moved to
// `crate::vault_ops::history`, but `keepass-merge` imports it from
// `keepass_core::kdbx::compute_history_drop_count`. Keep that public path
// resolving from here (`pub`, not `pub(crate)`).
pub use crate::vault_ops::history::compute_history_drop_count;

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
    /// Optional in-memory wrap layer for protected-field plaintext.
    ///
    /// When `Some`, the unlock pipeline wraps every protected field's
    /// plaintext (entry password + custom fields with `protected =
    /// true`, including the same fields on history snapshots) and
    /// stores the wrapped bytes in the per-entry [`ProtectedFieldMap`].
    /// The matching plaintext slot in [`Entry::password`] /
    /// [`crate::model::CustomField::value`] is cleared to an empty
    /// string so the canonical in-memory model never holds the
    /// cleartext after unlock. Save-time unwrap restores the plaintext
    /// on a local clone of the vault before the encoder runs.
    ///
    /// When `None`, behaviour matches the pre-protector default:
    /// plaintext rides in the model `String` fields exactly as it
    /// does today. See [`crate::protector`] for the trait contract.
    protector: Option<Arc<dyn FieldProtector>>,
    /// Per-entry map of wrapped protected-field bytes.
    ///
    /// Empty when [`Self::protector`] is `None`. Otherwise keyed by
    /// [`EntryId`]; the value carries the wrapped password and any
    /// wrapped custom-field values for that entry's current state and
    /// every history snapshot. See [`ProtectedFields`] for shape.
    protected_fields: ProtectedFieldMap,
}

/// Side-table of wrapped protected-field bytes keyed by [`EntryId`].
///
/// Populated on unlock when a [`FieldProtector`] is configured; the
/// in-model [`Entry::password`] / [`crate::model::CustomField::value`]
/// strings are cleared in tandem so plaintext is not duplicated in
/// memory. Reveal-side accessors and the save pipeline consult this
/// table to recover the plaintext on demand.
type ProtectedFieldMap = std::collections::HashMap<EntryId, ProtectedFields>;

/// Wrapped protected-field bytes for a single [`Entry`] and its
/// [`history`](Entry::history) snapshots.
///
/// The shape mirrors the entry model: the entry's password lives in
/// [`Self::password`]; per-key custom fields live in
/// [`Self::custom_fields`]; one [`Self::history`] entry exists per
/// history snapshot, in the same order as
/// [`Entry::history`](crate::model::Entry::history).
#[derive(Debug, Clone, Default)]
struct ProtectedFields {
    /// Wrapped bytes for the entry's password. `None` means the
    /// password was empty at unlock time (and remains empty after
    /// wrap, since wrapping an empty string is meaningless and would
    /// just add an empty-wrap round-trip cost for no benefit).
    password: Option<Vec<u8>>,
    /// Wrapped bytes for each `CustomField` with `protected = true`,
    /// keyed by `CustomField::key`. Non-protected custom fields are
    /// not included.
    custom_fields: std::collections::HashMap<String, Vec<u8>>,
    /// One entry per snapshot in [`Entry::history`](crate::model::Entry::history),
    /// in the same order. Each carries the wrapped form of the
    /// snapshot's password and protected custom fields.
    history: Vec<ProtectedFields>,
}

/// Inner-stream cipher parameters retained across [`Kdbx::<Unlocked>`]
/// for symmetric re-encryption on [`save_to_bytes`](Kdbx::save_to_bytes).
///
/// `key` is the inner-stream cipher key (Salsa20 or ChaCha20) used to
/// XOR-encode protected `<Value>` payloads in the XML. It lives for
/// the entire unlocked session, so it gets the same `ZeroizeOnDrop`
/// treatment as the other key-bearing types ([`CompositeKey`],
/// [`TransformedKey`], etc.) — wiped from the heap when the
/// [`Kdbx<Unlocked>`] is dropped.
#[derive(Clone, ZeroizeOnDrop)]
struct InnerStreamParams {
    #[zeroize(skip)]
    algorithm: InnerStreamAlgorithm,
    key: Vec<u8>,
}

impl std::fmt::Debug for InnerStreamParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InnerStreamParams")
            .field("algorithm", &self.algorithm)
            .field("key", &format_args!("[redacted; {} bytes]", self.key.len()))
            .finish()
    }
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
    /// 5. Decrypt with the outer cipher (AES-256-CBC and ChaCha20 are
    ///    supported; Twofish-CBC is rejected with an explicit error).
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
    ///
    /// # Threat-model note: KDBX3 outer headers are unauthenticated
    ///
    /// KDBX3 has no header HMAC. Every field used to derive the cipher
    /// key — `MasterSeed`, `TransformSeed`, `TransformRounds`,
    /// `EncryptionIv`, the inner-stream key — sits in the outer header
    /// in the clear and unauthenticated. An attacker who can substitute
    /// a file in place can mount a chosen-IV / chosen-seed attack
    /// against the AES-256-CBC ciphertext, and only the encrypted
    /// stream-start-bytes sentinel detects tampering after a successful
    /// decrypt. The KDF-parameter caps applied here (AES-KDF rounds,
    /// Argon2 memory / iterations / parallelism) blunt the DoS shape of
    /// a hostile header, but the format itself cannot be made
    /// confidentiality-secure against an adversary with file-substitute
    /// power. Prefer **KDBX4** for any threat model that includes
    /// adversarially-crafted files; KDBX4's `HeaderHmac` is verified
    /// before any payload decryption begins.
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

    /// Like [`Self::unlock`] but installs a [`FieldProtector`] so
    /// protected-field plaintext is wrapped at the wrap boundary and
    /// not held as a `String` on the in-memory model.
    ///
    /// After unlock, the configured protector is invoked once per
    /// protected field (entry password + each `protected = true`
    /// custom field on the current entry state and every history
    /// snapshot). The plaintext slot on the model is cleared to an
    /// empty `String`; the wrapped bytes live in an internal side
    /// table reachable via [`Kdbx::<Unlocked>::reveal_password`] and
    /// [`Kdbx::<Unlocked>::reveal_custom_field`]. On save the
    /// plaintext is reconstituted on a local clone of the vault
    /// before the encoder runs; the canonical in-memory state stays
    /// wrapped across the save.
    ///
    /// Passing `None` as the protector is equivalent to
    /// [`Self::unlock`]: no wrapping is performed and the model
    /// behaves exactly as it did before the trait existed.
    ///
    /// # Errors
    ///
    /// Same as [`Self::unlock`], plus [`Error::Protector`] if any
    /// `wrap` call fails on a non-empty protected field. A wrap
    /// failure surfaces immediately; the resulting `Kdbx` is
    /// discarded so a partially-wrapped vault is never exposed.
    pub fn unlock_with_protector(
        self,
        composite: &CompositeKey,
        protector: Option<Arc<dyn FieldProtector>>,
    ) -> Result<Kdbx<Unlocked>, Error> {
        self.unlock_with_clock_and_protector(composite, Box::new(SystemClock), protector)
    }

    /// Combination of [`Self::unlock_with_clock`] and
    /// [`Self::unlock_with_protector`] — caller-supplied clock plus
    /// optional protector. Intended for tests; production callers
    /// pick one of the two narrower entry points.
    ///
    /// # Errors
    ///
    /// Same as [`Self::unlock_with_protector`].
    pub fn unlock_with_clock_and_protector(
        self,
        composite: &CompositeKey,
        clock: Box<dyn Clock>,
        protector: Option<Arc<dyn FieldProtector>>,
    ) -> Result<Kdbx<Unlocked>, Error> {
        let mut state = do_unlock(&self.bytes, &self.state, composite)?;
        state.clock = clock;
        if let Some(p) = protector {
            state.protected_fields = wrap_vault_protected_fields(&mut state.vault, p.as_ref())?;
            state.protector = Some(p);
        }
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
    /// Build a fresh, in-memory KDBX4 vault, ready to
    /// [`save_to_bytes`](Self::save_to_bytes).
    ///
    /// Sensible defaults: AES-256-CBC outer cipher, Argon2d KDF (2 iter ×
    /// 64 MiB × 8 threads — matches contemporary KeePass / KeePassXC
    /// defaults), GZip compression, ChaCha20 inner stream. Random
    /// 32-byte master seed and 16-byte encryption IV from `OsRng`; random
    /// 32-byte Argon2 salt; random 64-byte inner-stream header key (the
    /// KeePass-spec post-SHA-512 derivation produces the ChaCha20 key +
    /// nonce). `database_name` is set both on `Meta::database_name` and as
    /// the root group's display name; the host frontend can rename the
    /// root group later if needed.
    ///
    /// The transformed key is derived **eagerly** from `composite` against
    /// the freshly-generated Argon2 parameters — call cost is one full
    /// Argon2 round (~1s at 64 MiB / 2 iter on contemporary hardware).
    /// The resulting [`Kdbx<Unlocked>`] is structurally identical to one
    /// obtained via `Kdbx::open(path).read_header().unlock(composite)` for
    /// a freshly-saved file (verified by round-trip tests below).
    ///
    /// Companion entry point to [`Kdbx::<Sealed>::open_from_bytes`] for
    /// downstream consumers that need to create a vault without first
    /// going through a placeholder file on disk.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if `getrandom` can't produce the seed/IV/
    /// salt/inner-stream bytes (effectively impossible — OS RNG would have
    /// to be unavailable), or if the Argon2 derivation rejects the
    /// parameters (also impossible at the values picked here — they're well
    /// above the spec minimums and validated against `argon2`'s acceptable
    /// range during development).
    pub fn create_empty_v4(
        composite: &CompositeKey,
        database_name: impl Into<String>,
    ) -> Result<Self, Error> {
        Self::create_empty_v4_inner(
            composite,
            database_name.into(),
            None,
            Box::new(SystemClock),
            &RandomUuids,
        )
    }

    /// Like [`Self::create_empty_v4`] but installs a
    /// [`FieldProtector`] for the fresh vault.
    ///
    /// The empty vault has no protected fields to wrap, so the
    /// protector is simply stored on the resulting [`Kdbx<Unlocked>`]
    /// and used as entries are added (their freshly-set password /
    /// custom-field values are wrapped via the entry editor before
    /// any subsequent save). Passing `None` is equivalent to
    /// [`Self::create_empty_v4`].
    ///
    /// # Errors
    ///
    /// Same as [`Self::create_empty_v4`].
    pub fn create_empty_v4_with_protector(
        composite: &CompositeKey,
        database_name: impl Into<String>,
        protector: Option<Arc<dyn FieldProtector>>,
    ) -> Result<Self, Error> {
        Self::create_empty_v4_inner(
            composite,
            database_name.into(),
            protector,
            Box::new(SystemClock),
            &RandomUuids,
        )
    }

    /// Like [`Self::create_empty_v4_with_protector`] but with the
    /// creation [`Clock`] and root-id [`UuidSource`] injected, so a fresh
    /// vault is byte-reproducible.
    ///
    /// `clock` stamps the root group's [`Timestamps`](crate::model::Timestamps) (and is retained on
    /// the unlocked vault for later mutations, exactly as `unlock`'s clock
    /// is); `uuids` mints the root [`GroupId`]. Pass a
    /// [`crate::model::FixedClock`] + [`crate::model::SeededUuids`] to make
    /// `create → save` produce the same logical vault every run (the KDBX
    /// *bytes* still differ — master seed / IV / KDF salt are fresh OS
    /// randomness each save — but the entity ids and timestamps that drive
    /// sync are pinned). The default [`Self::create_empty_v4`] uses
    /// [`SystemClock`] + [`RandomUuids`].
    ///
    /// Only the root id is drawn here; a caller that wants further
    /// creation ids pinned (e.g. an eager recycle bin) should draw them
    /// from the *same* `uuids` instance and pass them explicitly via
    /// [`NewGroup::with_uuid`], so the whole create shares one coherent
    /// id sequence.
    ///
    /// # Errors
    ///
    /// Same as [`Self::create_empty_v4`].
    pub fn create_empty_v4_deterministic(
        composite: &CompositeKey,
        database_name: impl Into<String>,
        protector: Option<Arc<dyn FieldProtector>>,
        clock: Box<dyn Clock>,
        uuids: &dyn UuidSource,
    ) -> Result<Self, Error> {
        Self::create_empty_v4_inner(composite, database_name.into(), protector, clock, uuids)
    }

    /// Shared core of the `create_empty_v4*` family: builds a fresh KDBX4
    /// vault with one empty root group, deriving the transformed key
    /// against freshly-generated Argon2 params. The clock, root-id source,
    /// and protector are injected so the public wrappers can fix
    /// production defaults ([`SystemClock`] + [`RandomUuids`] + no
    /// protector) or pin them for reproducible tests/fuzzing.
    fn create_empty_v4_inner(
        composite: &CompositeKey,
        database_name: String,
        protector: Option<Arc<dyn FieldProtector>>,
        clock: Box<dyn Clock>,
        uuids: &dyn UuidSource,
    ) -> Result<Self, Error> {
        // Fresh randomness. Single getrandom batch per buffer; failures
        // collapse to CryptoError::Decrypt because the call sites all
        // share that error variant (see `rekey` for the same pattern).
        let mut master_seed = [0u8; 32];
        getrandom::fill(&mut master_seed).map_err(|_| Error::Crypto(CryptoError::Decrypt))?;
        let mut encryption_iv = vec![0u8; 16]; // AES-256-CBC block size.
        getrandom::fill(&mut encryption_iv).map_err(|_| Error::Crypto(CryptoError::Decrypt))?;
        let mut argon2_salt = vec![0u8; 32];
        getrandom::fill(&mut argon2_salt).map_err(|_| Error::Crypto(CryptoError::Decrypt))?;
        let mut inner_stream_key = vec![0u8; 64]; // KeePass convention.
        getrandom::fill(&mut inner_stream_key).map_err(|_| Error::Crypto(CryptoError::Decrypt))?;

        // Argon2d defaults — match contemporary KeePass / KeePassXC writer
        // defaults. Iterations = 2, memory = 64 MiB, parallelism = 8.
        let kdf_params = KdfParams::Argon2 {
            variant: Argon2Variant::Argon2d,
            salt: argon2_salt.clone(),
            iterations: 2,
            memory_bytes: 64 * 1024 * 1024,
            parallelism: 8,
            version: Argon2Version::V13,
        };
        let kdf_params_blob = kdf_params
            .to_var_dictionary_blob()
            .map_err(|_| FormatError::MalformedHeader("failed to encode KDF parameters"))?;

        // Eager-derive the transformed key against the just-generated
        // Argon2 params. One full Argon2 round; ~1s on contemporary
        // hardware at these settings.
        let transformed_key =
            derive_transformed_key(composite, &kdf_params).map_err(|_| CryptoError::Kdf)?;

        let outer_header = OuterHeader {
            cipher_id: CipherId(CipherId::AES256_CBC),
            compression: CompressionFlags::Gzip,
            master_seed: MasterSeed(master_seed),
            encryption_iv: EncryptionIv(encryption_iv),
            // KDBX4 keeps KDF + custom-data as VarDictionary blobs in the
            // outer header; the KDBX3-only inner-stream fields are absent by
            // construction (the enum makes them unrepresentable on V4).
            version_fields: VersionFields::V4 {
                kdf_parameters: kdf_params_blob,
                public_custom_data: None,
            },
        };

        // Fresh vault: empty root group named after `database_name`, its id
        // drawn from the injected source. Root timestamps stay at
        // `Timestamps::default()` (as `Group::empty` sets them) — the
        // injected `clock` is retained on `Unlocked` and stamps subsequent
        // mutations (e.g. a caller's eager recycle bin via `add_group`),
        // matching how `unlock`'s clock behaves.
        let root_id = GroupId(uuids.next_uuid());
        let mut vault = Vault::empty(root_id);
        vault.meta.database_name.clone_from(&database_name);
        vault.root.name = database_name;

        Ok(Kdbx {
            bytes: Vec::new(),
            signature: FileSignature { major: 4, minor: 0 },
            version: Version::V4,
            state: Unlocked {
                vault,
                clock,
                outer_header,
                inner_stream: Some(InnerStreamParams {
                    algorithm: InnerStreamAlgorithm::ChaCha20,
                    key: inner_stream_key,
                }),
                transformed_key,
                protector,
                protected_fields: ProtectedFieldMap::new(),
            },
        })
    }

    /// The decoded vault.
    #[must_use]
    pub fn vault(&self) -> &Vault {
        &self.state.vault
    }

    /// The outer-header record preserved from disk through unlock.
    ///
    /// Read-only view over fields like [`OuterHeader::cipher_id`] and the
    /// version-specific [`OuterHeader::version_fields`] (KDF parameters,
    /// inner-stream knobs) — useful for downstream UI that wants to surface
    /// format-level metadata (cipher choice, KDF shape, KDBX version-specific
    /// knobs) without reaching for the raw byte slice.
    ///
    /// The header is captured at unlock time and not refreshed by
    /// mutations; KDBX4 saves regenerate the relevant fields
    /// (`master_seed`, `encryption_iv`, KDF-parameters salt) under
    /// the hood on the way out.
    #[must_use]
    pub fn outer_header(&self) -> &OuterHeader {
        &self.state.outer_header
    }

    /// The configured [`FieldProtector`], if any.
    ///
    /// `None` when the vault was unlocked via [`Self::unlock`] or
    /// constructed via [`Self::create_empty_v4`]; `Some(...)` when
    /// unlocked via [`Self::unlock_with_protector`] /
    /// [`Self::unlock_with_clock_and_protector`] or built via
    /// [`Self::create_empty_v4_with_protector`].
    #[must_use]
    pub fn field_protector(&self) -> Option<&Arc<dyn FieldProtector>> {
        self.state.protector.as_ref()
    }

    /// Return a clone of the vault with every protected field's
    /// plaintext spliced back into `Entry::password` and
    /// [`crate::model::CustomField::value`].
    ///
    /// Mirrors the unwrap step inside [`Self::save_to_bytes`]:
    /// mutates a local clone so the canonical
    /// `state.vault` stays in its wrapped / empty-plaintext shape and
    /// callers can't accidentally leak plaintext back into the
    /// long-lived model.
    ///
    /// Intended for downstream consumers that need a fully-realised
    /// [`Vault`] for byte-level work outside the encoder — chiefly the
    /// 3-way merger, whose protected-field comparator otherwise sees
    /// empty strings on the wrapped side and full plaintext on the
    /// non-wrapped (file-loaded) side, falsely flagging every
    /// protected custom field as a conflict.
    ///
    /// When no [`FieldProtector`] is configured the clone is returned
    /// verbatim — `state.vault` already carries plaintext on that path.
    ///
    /// The returned [`Vault`] is owned by the caller; drop it as soon
    /// as the work is done to limit how long plaintext lingers in
    /// process memory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protector`] if the configured protector's
    /// `unwrap` rejects any wrapped blob or produces non-UTF-8 output.
    pub fn vault_with_unwrapped_protected(&self) -> Result<Vault, Error> {
        let mut vault = self.state.vault.clone();
        if let Some(protector) = self.state.protector.as_ref() {
            unwrap_vault_protected_fields(
                &mut vault,
                &self.state.protected_fields,
                protector.as_ref(),
            )?;
        }
        Ok(vault)
    }

    /// Reveal an entry's password as plaintext.
    ///
    /// When no protector is configured, returns the stored
    /// [`Entry::password`] verbatim (it already holds plaintext).
    /// When a protector is configured, looks up the wrapped bytes in
    /// the internal side table and unwraps via the protector. An
    /// empty password (no wrapped bytes recorded) returns
    /// `Ok(String::new())`.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::EntryNotFound`] if no entry matches
    /// `id`. Returns [`ProtectorError::KeyUnavailable`] or
    /// [`ProtectorError::Open`] (wrapped in [`Error::Protector`]) if
    /// the protector fails or the wrapped bytes can't be opened /
    /// produce non-UTF-8 output.
    pub fn reveal_password(&self, id: EntryId) -> Result<String, Error> {
        let entry = self
            .state
            .vault
            .root
            .entry(id)
            .ok_or(ModelError::EntryNotFound(id))?;
        match (
            self.state.protector.as_ref(),
            self.state.protected_fields.get(&id),
        ) {
            (Some(protector), Some(record)) => match &record.password {
                Some(bytes) => {
                    let key = protector.acquire_session_key()?;
                    Ok(decode_wrapped_with_key(bytes, &key)?)
                }
                None => Ok(String::new()),
            },
            _ => Ok(entry.password.clone()),
        }
    }

    /// Reveal a custom field's value as plaintext.
    ///
    /// `Ok(None)` when no custom field with `key` exists on the
    /// entry. For non-protected custom fields, returns the stored
    /// value verbatim (it is already plaintext regardless of whether
    /// a protector is configured). For protected custom fields,
    /// behaves analogously to [`Self::reveal_password`].
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::EntryNotFound`] if no entry matches
    /// `id`. Returns [`ProtectorError::KeyUnavailable`] or
    /// [`ProtectorError::Open`] (wrapped in [`Error::Protector`]) on
    /// protector failure or non-UTF-8 output.
    pub fn reveal_custom_field(&self, id: EntryId, key: &str) -> Result<Option<String>, Error> {
        let entry = self
            .state
            .vault
            .root
            .entry(id)
            .ok_or(ModelError::EntryNotFound(id))?;
        let Some(cf) = entry.custom_fields.iter().find(|c| c.key == key) else {
            return Ok(None);
        };
        if !cf.protected {
            return Ok(Some(cf.value.clone()));
        }
        match (
            self.state.protector.as_ref(),
            self.state.protected_fields.get(&id),
        ) {
            (Some(protector), Some(record)) => match record.custom_fields.get(key) {
                Some(bytes) => {
                    let session_key = protector.acquire_session_key()?;
                    Ok(Some(decode_wrapped_with_key(bytes, &session_key)?))
                }
                None => Ok(Some(String::new())),
            },
            _ => Ok(Some(cf.value.clone())),
        }
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
        vault_ops::meta_settings::replace_vault(&mut self.state.vault, vault);
    }

    /// Insert a new [`Entry`] under the group identified by `parent`.
    ///
    /// The library owns UUID generation (unless the builder set one
    /// via [`NewEntry::with_uuid`]), fills in every
    /// [`Timestamps`](crate::model::Timestamps) field from [`Self::clock`], sets
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
    /// Does not panic under any input. The second `group_mut`
    /// call is `.expect()`ed because the first call has already
    /// proved the group exists.
    pub fn add_entry(
        &mut self,
        parent: GroupId,
        template: NewEntry,
    ) -> Result<EntryId, ModelError> {
        let Unlocked { vault, clock, .. } = &mut self.state;
        vault_ops::entry_ops::add_entry(vault, clock.as_ref(), parent, template)
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
        let Unlocked { vault, clock, .. } = &mut self.state;
        vault_ops::entry_ops::delete_entry(vault, clock.as_ref(), id)
    }

    /// Move an entry from its current parent to `new_parent`.
    ///
    /// Bookkeeping applied automatically:
    /// - `entry.times.location_changed = self.clock().now()`
    /// - `entry.previous_parent_group = Some(old_parent)`
    /// - No history snapshot — the design notes §"Bookkeeping invariants"
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
    /// Does not panic under any input. The second `group_mut`
    /// call is `.expect()`ed because the first call has already
    /// proved the destination exists.
    pub fn move_entry(&mut self, id: EntryId, new_parent: GroupId) -> Result<(), ModelError> {
        let Unlocked { vault, clock, .. } = &mut self.state;
        vault_ops::entry_ops::move_entry(vault, clock.as_ref(), id, new_parent)
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
    /// - [`ModelError::Protector`] when a [`FieldProtector`] is
    ///   configured and `wrap` fails while rewrapping the live
    ///   protected slots after the closure runs. In practice
    ///   production protectors do not fail on wrap, but the error is
    ///   surfaced so callers can route the failure rather than
    ///   silently leaving plaintext on the model.
    ///
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
        // Capture the protector + the pre-edit wrapped record so the
        // editor closure can operate on plaintext, then we re-wrap
        // everything (live fields + every history snapshot) once it
        // returns. When no protector is configured the unwrap/rewrap
        // bookkeeping is skipped entirely.
        let protector = self.state.protector.clone();
        let old_record = protector
            .as_ref()
            .and_then(|_| self.state.protected_fields.get(&id).cloned());

        let entry = self
            .state
            .vault
            .root
            .entry_mut(id)
            .ok_or(ModelError::EntryNotFound(id))?;

        // Restore plaintext on the entry from the side-table so the
        // editor closure reads "current" values from `entry.password`
        // / protected custom fields, and any snapshot we clone next
        // captures the up-to-date plaintext for save-time use. This
        // mirror's the save pipeline's `unwrap_vault_protected_fields`
        // step on a single entry.
        // Per-edit key: acquired once if a protector is configured AND
        // this entry has wrapped fields. Used for both the pre-edit
        // unwrap and the post-edit re-wrap below so the editor pays
        // a single `acquire_session_key` call per edit cycle.
        let edit_key = match (protector.as_ref(), old_record.as_ref()) {
            (Some(p), Some(_)) => Some(p.acquire_session_key()?),
            _ => None,
        };
        if let (Some(rec), Some(k)) = (old_record.as_ref(), edit_key.as_ref()) {
            unwrap_entry_with_key(entry, rec, k)?;
        }

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
        // Split-borrow: `entry` is &mut into `self.state.vault.root`;
        // the binary pool is a sibling field of the same Vault. Rust
        // allows holding both borrows simultaneously because they
        // target disjoint fields.
        let binaries: &[Binary] = &self.state.vault.binaries;
        let (result, pending) = {
            let mut editor = EntryEditor::new(entry, binaries);
            let r = f(&mut editor);
            let p = editor.take_pending_binary_ops();
            (r, p)
        };

        entry.times.last_modification_time = Some(now);

        // Re-wrap the entry's protected fields (live + every history
        // snapshot) into a fresh side-table record so the canonical
        // "model holds empty plaintext, side-table holds wrapped
        // bytes" invariant is restored. Without this the save-time
        // unwrap step blindly restores the OLD wrapped bytes over
        // whatever the editor wrote and the edit is lost.
        let new_record = match (protector.as_ref(), edit_key.as_ref()) {
            (Some(_), Some(k)) => Some(wrap_entry_with_key(entry, k)?),
            (Some(p), None) => {
                // Edit on an entry that didn't have a wrapped record
                // before this edit (e.g. all protected fields were
                // empty). Acquire a key now to wrap the new state.
                let k = p.acquire_session_key()?;
                Some(wrap_entry_with_key(entry, &k)?)
            }
            _ => None,
        };

        // The &mut Entry borrow ends here; from this point on we
        // have &mut Vault available for pool-level work.
        let _ = entry;

        apply_pending_attaches(&mut self.state.vault, id, pending);
        gc_binaries_pool(&mut self.state.vault);

        if let Some(new_record) = new_record {
            self.state.protected_fields.insert(id, new_record);
        }

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
    /// "clear last-access" button), use [`Self::clear_entry_last_access`]
    /// — the symmetric inverse, with the same explicit non-effects.
    /// Routing the clear through [`Self::edit_entry`] +
    /// [`crate::model::EntryEditor::set_last_access_time`] also works
    /// but additionally stamps `last_modification_time`, which is not
    /// what a "wipe the access stamp" action typically intends.
    ///
    /// # Errors
    ///
    /// - [`ModelError::EntryNotFound`] if `id` is not in the vault.
    pub fn touch_entry(&mut self, id: EntryId) -> Result<(), ModelError> {
        let Unlocked { vault, clock, .. } = &mut self.state;
        vault_ops::entry_ops::touch_entry(vault, clock.as_ref(), id)
    }

    /// Clear `entry.times.last_access_time` on the entry identified
    /// by `id`, returning the field to `None`. The symmetric inverse
    /// of [`Self::touch_entry`].
    ///
    /// Explicit non-effects (asserted by integration tests):
    ///
    /// - No history snapshot. Wiping the access stamp is not a
    ///   content edit.
    /// - No [`crate::model::Meta::settings_changed`] stamp.
    /// - No [`crate::model::Timestamps::last_modification_time`]
    ///   update. The entry's content hasn't changed; the "recently
    ///   modified" sort shouldn't move because the user cleared an
    ///   access record.
    /// - No [`crate::model::Timestamps::location_changed`] update.
    /// - No binary-pool GC. Refcounts are unaffected.
    ///
    /// # Errors
    ///
    /// - [`ModelError::EntryNotFound`] if `id` is not in the vault.
    pub fn clear_entry_last_access(&mut self, id: EntryId) -> Result<(), ModelError> {
        vault_ops::entry_ops::clear_entry_last_access(&mut self.state.vault, id)
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
    /// 8. When a [`FieldProtector`] is configured, re-wrap the restored
    ///    entry (live protected fields + every surviving history
    ///    snapshot) into a fresh side-table record, exactly as
    ///    [`Self::edit_entry`] does. The protected-field plaintext for a
    ///    protector-backed vault lives in the side-table, not the model
    ///    `String`s; without this step the save pipeline's unwrap pass
    ///    would overlay the STALE pre-restore wrapped bytes over the
    ///    restored plaintext and the restore would be silently lost on
    ///    save. No-op when no protector is configured (the non-protector
    ///    path is behaviour-identical to before).
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
    /// - [`ModelError::Protector`] when a [`FieldProtector`] is
    ///   configured and acquiring the session key, unwrapping the
    ///   pre-restore snapshot plaintext, or re-wrapping the restored
    ///   fields fails. In practice production protectors do not fail,
    ///   but the error is surfaced so callers can route the failure
    ///   rather than persisting a half-restored side-table.
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
        // Capture the protector + the pre-restore wrapped record so we
        // can unwrap the live entry (and its history snapshots) to
        // plaintext before reading the target snapshot, then re-wrap the
        // restored entry into a fresh side-table record afterwards.
        // Mirror of `edit_entry`: with a protector configured the model
        // `String`s are blanked and the real bytes live in the
        // side-table, so a raw `snap.password` read would see the empty
        // post-wrap string and the side-table would still point at the
        // pre-restore ciphertext. When no protector is configured all of
        // this is skipped and the path is behaviour-identical to before.
        let protector = self.state.protector.clone();
        let old_record = protector
            .as_ref()
            .and_then(|_| self.state.protected_fields.get(&id).cloned());

        let entry = self
            .state
            .vault
            .root
            .entry_mut(id)
            .ok_or(ModelError::EntryNotFound(id))?;

        if history_index >= entry.history.len() {
            return Err(ModelError::HistoryIndexOutOfRange {
                id,
                index: history_index,
                len: entry.history.len(),
            });
        }

        // Per-restore key: acquired once if a protector is configured
        // AND this entry has wrapped fields. Used for both the
        // pre-restore unwrap and the post-restore re-wrap so we pay a
        // single `acquire_session_key` call per restore.
        let restore_key = match (protector.as_ref(), old_record.as_ref()) {
            (Some(p), Some(_)) => Some(p.acquire_session_key()?),
            _ => None,
        };
        // Restore plaintext onto the live entry and every history
        // snapshot from the side-table, so the snapshot we clone next
        // carries real plaintext (not the blanked post-wrap string) and
        // any pre-restore snapshot we push captures live plaintext.
        if let (Some(rec), Some(k)) = (old_record.as_ref(), restore_key.as_ref()) {
            unwrap_entry_with_key(entry, rec, k)?;
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

        // Re-wrap the restored entry (live protected fields + every
        // surviving history snapshot) into a fresh side-table record so
        // the canonical "model holds empty plaintext, side-table holds
        // wrapped bytes" invariant is restored around the new content.
        // Truncation ran first, so the record's history aligns
        // positionally with `entry.history`. Without this the save-time
        // unwrap step blindly overlays the OLD wrapped bytes over the
        // restored plaintext and the restore is lost on save. Mirror of
        // `edit_entry`'s post-edit re-wrap.
        let new_record = match (protector.as_ref(), restore_key.as_ref()) {
            (Some(_), Some(k)) => Some(wrap_entry_with_key(entry, k)?),
            (Some(p), None) => {
                // Restore on an entry that had no wrapped record before
                // (e.g. all protected fields were empty at unlock).
                // Acquire a key now to wrap the restored state.
                let k = p.acquire_session_key()?;
                Some(wrap_entry_with_key(entry, &k)?)
            }
            _ => None,
        };

        // End the entry borrow so the vault is accessible again for
        // pool GC.
        let _ = entry;
        gc_binaries_pool(&mut self.state.vault);

        if let Some(new_record) = new_record {
            self.state.protected_fields.insert(id, new_record);
        }

        Ok(())
    }

    /// Apply the vault's current
    /// [`crate::model::Meta::history_max_items`] +
    /// [`crate::model::Meta::history_max_size`] limits to one entry's
    /// `history` list. Returns the number of snapshots dropped.
    ///
    /// This is the same truncation pass [`Self::edit_entry`] runs
    /// after pushing a fresh snapshot, exposed as a standalone
    /// operation so callers can re-apply the current limits without
    /// performing a content edit — useful after the user lowers
    /// `history_max_items` or `history_max_size` and wants the new
    /// caps to take immediate effect across existing entries.
    ///
    /// Semantics match the in-edit truncation:
    /// - Negative limits mean "unlimited" and skip that budget.
    /// - The item-count budget is enforced first.
    /// - The size budget is an approximate soft cap on serialised
    ///   canonical-field byte count; entries are dropped oldest-first
    ///   until the estimate fits.
    ///
    /// Like [`Self::prune_history_older_than`], this is a bookkeeping
    /// operation, not a content edit:
    /// `entry.times.last_modification_time` is **not** stamped, and
    /// [`crate::model::Meta::settings_changed`] is **not** touched.
    ///
    /// # Errors
    ///
    /// - [`ModelError::EntryNotFound`] if `id` is not in the vault.
    pub fn trim_entry_history(&mut self, id: EntryId) -> Result<u32, ModelError> {
        vault_ops::entry_ops::trim_entry_history(&mut self.state.vault, id)
    }

    /// Drop every history snapshot whose own
    /// [`crate::model::Timestamps::last_modification_time`] is older
    /// than `cutoff`, across the entire vault. Returns the total
    /// number of snapshots removed.
    ///
    /// Pruning is a *bookkeeping* operation, not a content edit:
    /// `entry.times.last_modification_time` is **not** stamped on the
    /// affected live entries. This matches how the auto-truncation
    /// path in [`Self::edit_entry`] already behaves — silent
    /// trimming of the history list, no live-side timestamp churn.
    ///
    /// Snapshots whose own `last_modification_time` is `None` are
    /// treated as ancient and pruned, mirroring the
    /// `is_none_or` rule in
    /// [`crate::model::HistoryPolicy::SnapshotIfOlderThan`].
    ///
    /// `meta.settings_changed` is **not** stamped — pruning
    /// touches per-entry history, not Meta. No `DeletedObject`
    /// records are written: history snapshots are a per-entry
    /// implementation detail, not first-class vault objects.
    pub fn prune_history_older_than(&mut self, cutoff: chrono::DateTime<chrono::Utc>) -> usize {
        vault_ops::entry_ops::prune_history_older_than(&mut self.state.vault, cutoff)
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
        let Unlocked { vault, clock, .. } = &mut self.state;
        vault_ops::icons::add_custom_icon(vault, clock.as_ref(), data)
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
        let Unlocked { vault, clock, .. } = &mut self.state;
        vault_ops::icons::remove_custom_icon(vault, clock.as_ref(), id)
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
        vault_ops::icons::custom_icon(&self.state.vault, id)
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
        let entry = self
            .state
            .vault
            .root
            .entry(id)
            .ok_or(ModelError::EntryNotFound(id))?;

        // Collect the set of binary ref_ids referenced by the entry
        // or any of its history snapshots. Same live+history walk the
        // binary-pool GC (`gc_binaries_pool`) does over the whole tree.
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
    /// Does not panic under any input. The second `group_mut`
    /// call after UUID validation is `.expect()`ed because the
    /// first call has already proved the parent exists.
    pub fn import_entry(
        &mut self,
        parent: GroupId,
        mut entry: PortableEntry,
        mint_new_uuid: bool,
    ) -> Result<EntryId, ModelError> {
        if self.state.vault.root.group(parent).is_none() {
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

        // Stamp live-entry bookkeeping per the design notes invariants.
        entry.entry.times.creation_time = Some(now);
        entry.entry.times.last_modification_time = Some(now);
        entry.entry.times.last_access_time = Some(now);
        entry.entry.times.location_changed = Some(now);
        entry.entry.times.usage_count = 0;
        entry.entry.previous_parent_group = None;

        let new_id = entry.entry.id;
        let target = self
            .state
            .vault
            .root
            .group_mut(parent)
            .expect("parent existence checked at the top of this method");
        target.entries.push(entry.entry);
        Ok(new_id)
    }

    /// Import a previously-exported entry under `parent`, restoring
    /// it under the explicit `target_uuid` rather than minting a new
    /// id or preserving the carrier's UUID verbatim.
    ///
    /// Intended for **move-undo across vaults**: a forward cross-vault
    /// move runs `export_entry` (on the source) → `import_entry`
    /// (mint a new UUID on the target) → `delete_entry` (on the
    /// source). Undoing that bounce normally produces a *third* UUID
    /// because the standard `import_entry(mint_new_uuid: true)` mints
    /// again — external references pinned to the pre-move UUID
    /// (`AutoFill` record identifiers, bookmarks, links) then break.
    /// This method lets the caller specify the original UUID so the
    /// undo restores the pre-move identity.
    ///
    /// **Tombstone handling.** Any matching entry in
    /// `vault.deleted_objects` (the source-side tombstone from the
    /// forward move's [`Self::delete_entry`]) is removed before
    /// importing. Semantically, the move-and-delete is being undone,
    /// so the "this entry was deleted" record shouldn't survive into
    /// the post-undo state where the entry is alive again. Without
    /// this step, a downstream merge against another vault could see
    /// the tombstone and re-delete the freshly-restored entry.
    ///
    /// **History snapshots** still receive freshly-minted UUIDs (same
    /// as the `mint_new_uuid: true` branch of [`Self::import_entry`])
    /// — history-snapshot UUIDs are local-to-vault; preserving them
    /// across a round-trip carries no semantic value and risks
    /// `DuplicateUuid` against unrelated history.
    ///
    /// Everything else (binary / icon dedup, time-stamp bookkeeping,
    /// non-stamping of `Meta::settings_changed`) matches
    /// [`Self::import_entry`].
    ///
    /// # Errors
    ///
    /// - [`ModelError::GroupNotFound`] if `parent` isn't in the vault.
    /// - [`ModelError::DuplicateUuid`] if `target_uuid` is already in
    ///   use as a live entry (or as a live group, or in the history
    ///   of a live entry). Tombstones don't count and are cleared
    ///   silently regardless of the outcome.
    pub fn import_entry_with_uuid(
        &mut self,
        parent: GroupId,
        mut entry: PortableEntry,
        target_uuid: EntryId,
    ) -> Result<EntryId, ModelError> {
        // Override the live entry's UUID to the caller-specified one.
        // History snapshots get fresh UUIDs — see the doc comment.
        entry.entry.id = target_uuid;
        for snap in &mut entry.entry.history {
            snap.id = EntryId(fresh_uuid(&self.state.vault));
        }

        // Forgive any matching tombstone before the import collision
        // check runs (uuid_in_use ignores tombstones, but downstream
        // sync would consume the tombstone as "delete this entry"
        // and undo the undo).
        self.state
            .vault
            .deleted_objects
            .retain(|t| t.uuid != target_uuid.0);

        // Delegate to import_entry with the preserve-UUID branch. Its
        // uuid_in_use check catches the case where target_uuid is
        // already live in the destination vault (legitimately a
        // bookkeeping error from the caller).
        self.import_entry(parent, entry, false)
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
        let parent = self
            .state
            .vault
            .root
            .entry_parent(id)
            .ok_or(ModelError::EntryNotFound(id))?;

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
            if self
                .state
                .vault
                .root
                .group(bin_id)
                .is_some_and(|bin| bin.group(parent).is_some())
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
        if self.state.vault.root.group(id).is_none() {
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
            if bin_id == id && self.state.vault.root.group(bin_id).is_some() {
                return Err(ModelError::CircularMove {
                    moving: id,
                    new_parent: bin_id,
                });
            }
            // Already inside the bin?
            if self
                .state
                .vault
                .root
                .group(bin_id)
                .is_some_and(|bin| bin.group(id).is_some())
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
        let Some(bin) = self.state.vault.root.group(bin_id) else {
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
            if self.state.vault.root.group(bin_id).is_some() {
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
    /// Reuses the outer-header framing (cipher, KDF parameters) that
    /// was parsed at unlock time, plus the transformed key cached in
    /// the [`Unlocked`] state so no second round of Argon2 is needed.
    /// The encryption IV and master seed are regenerated per save so
    /// that the outer cipher (key, nonce) pair never repeats across
    /// successive saves under the same composite key.
    ///
    /// # Durability is the caller's responsibility
    ///
    /// `save_to_bytes` returns an in-memory `Vec<u8>`. **Do not**
    /// `fs::write(path, kdbx.save_to_bytes()?)` directly — that
    /// truncates the destination before writing, so a crash mid-write
    /// produces a zero-byte or partially-written kdbx file and the
    /// user's vault is gone. Callers persisting to disk must perform
    /// the write atomically:
    ///
    /// 1. Write the bytes to a sibling tempfile on the **same volume**
    ///    as the target (so the rename is atomic — a cross-volume
    ///    rename falls back to copy-and-delete and re-opens the
    ///    truncation window).
    /// 2. `fsync` the tempfile so its data hits stable storage.
    /// 3. `rename(2)` the tempfile over the target — atomic at the
    ///    POSIX layer.
    /// 4. `fsync` the parent directory so the rename is durable.
    ///
    /// `tempfile::NamedTempFile::new_in(parent).persist(path)` plus
    /// `sync_all` on the file and the parent directory implements
    /// the full dance.
    ///
    /// The library deliberately stops at bytes-in-memory: callers run
    /// under sandboxes (macOS security-scoped bookmarks, iOS file
    /// providers, browser FileSystemAccess) whose I/O constraints
    /// differ enough that a `save_to_path` helper would have to grow
    /// a configuration surface comparable to the I/O step itself.
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

    /// Insert a new [`Group`](crate::model::Group) under the parent identified by
    /// `parent`.
    ///
    /// Mirrors [`Self::add_entry`]: the library owns UUID generation
    /// (unless the builder set one via [`NewGroup::with_uuid`]),
    /// fills in every [`Timestamps`](crate::model::Timestamps) field from [`Self::clock`],
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
    /// Does not panic under any input. The second `group_mut`
    /// call is `.expect()`ed because the first call has already
    /// proved the parent exists.
    pub fn add_group(
        &mut self,
        parent: GroupId,
        template: NewGroup,
    ) -> Result<GroupId, ModelError> {
        let Unlocked { vault, clock, .. } = &mut self.state;
        vault_ops::group_ops::add_group(vault, clock.as_ref(), parent, template)
    }

    /// Recursively delete the group with the given id.
    ///
    /// Every entry and every subgroup under the target gets its own
    /// [`DeletedObject`](crate::model::DeletedObject) tombstone (stamped from [`Self::clock`])
    /// before the subtree is removed, so a peer replica merging
    /// against this vault can tell deleted records apart from
    /// never-seen ones.
    ///
    /// # Errors
    ///
    /// - [`ModelError::CannotDeleteRoot`] if `id` is the root group's id.
    /// - [`ModelError::GroupNotFound`] if `id` is not in the vault.
    pub fn delete_group(&mut self, id: GroupId) -> Result<(), ModelError> {
        let Unlocked { vault, clock, .. } = &mut self.state;
        vault_ops::group_ops::delete_group(vault, clock.as_ref(), id)
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
    /// Does not panic under any input. The final `group_mut`
    /// call is `.expect()`ed because the destination's existence was
    /// already proved earlier in the function.
    pub fn move_group(&mut self, id: GroupId, new_parent: GroupId) -> Result<(), ModelError> {
        let Unlocked { vault, clock, .. } = &mut self.state;
        vault_ops::group_ops::move_group(vault, clock.as_ref(), id, new_parent)
    }

    /// Move a group from its current parent to `new_parent`, inserting
    /// it at the given `position` among `new_parent`'s children.
    ///
    /// Same bookkeeping and same error semantics as [`Self::move_group`]
    /// — the only difference is the insertion point. A `position`
    /// greater than the destination's current child count is clamped to
    /// the end (i.e. equivalent to a push), matching the "out-of-range
    /// is append" convention used by typical drag-and-drop reordering
    /// UIs.
    ///
    /// When the source's old parent and `new_parent` are the same
    /// group, this is a sibling reorder: the source is removed first,
    /// then re-inserted at `position` *relative to the remaining
    /// siblings*. Callers that want a stable "insert before sibling X"
    /// semantic should compute X's index in the post-removal list.
    ///
    /// # Errors
    ///
    /// - [`ModelError::CannotDeleteRoot`] if `id` is the root group.
    /// - [`ModelError::GroupNotFound`] if either `id` or `new_parent`
    ///   is missing.
    /// - [`ModelError::CircularMove`] if the move would create a cycle.
    ///
    /// # Panics
    ///
    /// Does not panic under any input. The final `group_mut`
    /// call is `.expect()`ed because the destination's existence was
    /// already proved earlier in the function.
    pub fn move_group_to_position(
        &mut self,
        id: GroupId,
        new_parent: GroupId,
        position: usize,
    ) -> Result<(), ModelError> {
        let Unlocked { vault, clock, .. } = &mut self.state;
        vault_ops::group_ops::move_group_to_position(
            vault,
            clock.as_ref(),
            id,
            new_parent,
            position,
        )
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
        let Unlocked { vault, clock, .. } = &mut self.state;
        vault_ops::group_ops::edit_group(vault, clock.as_ref(), id, f)
    }

    // -----------------------------------------------------------------
    // Meta setters
    // -----------------------------------------------------------------
    //
    // Each setter writes the requested field on `vault.meta` and
    // stamps `meta.settings_changed = clock.now()`. The high-level
    // setter API deliberately does not auto-stamp the per-field
    // `*Changed` timestamps (`database_name_changed` and friends) —
    // those are KeePass's own field-level edit-history hooks and are
    // left for the caller to manage. Encoder and decoder still
    // round-trip them faithfully when set in-model.

    /// Set the user-visible vault name.
    pub fn set_database_name(&mut self, name: impl Into<String>) {
        let Unlocked { vault, clock, .. } = &mut self.state;
        vault_ops::meta_settings::set_database_name(vault, clock.as_ref(), name);
    }

    /// Set the user-visible free-text vault description.
    pub fn set_database_description(&mut self, description: impl Into<String>) {
        let Unlocked { vault, clock, .. } = &mut self.state;
        vault_ops::meta_settings::set_database_description(vault, clock.as_ref(), description);
    }

    /// Set the default username used for new entries.
    pub fn set_default_username(&mut self, username: impl Into<String>) {
        let Unlocked { vault, clock, .. } = &mut self.state;
        vault_ops::meta_settings::set_default_username(vault, clock.as_ref(), username);
    }

    /// Set the vault-level colour swatch (hex `"#RRGGBB"`). Empty
    /// string falls back to the host client's default colour.
    pub fn set_color(&mut self, hex: impl Into<String>) {
        let Unlocked { vault, clock, .. } = &mut self.state;
        vault_ops::meta_settings::set_color(vault, clock.as_ref(), hex);
    }

    /// Configure the recycle bin: whether soft-delete is enabled, and
    /// which group acts as the bin. Pass `None` to clear the bin
    /// reference (the on-disk encoding then surfaces as either an
    /// absent or all-zero UUID).
    pub fn set_recycle_bin(&mut self, enabled: bool, group: Option<GroupId>) {
        let Unlocked { vault, clock, .. } = &mut self.state;
        vault_ops::meta_settings::set_recycle_bin(vault, clock.as_ref(), enabled, group);
    }

    /// Cap entry-history length. `-1` means unlimited.
    pub fn set_history_max_items(&mut self, max: i32) {
        let Unlocked { vault, clock, .. } = &mut self.state;
        vault_ops::meta_settings::set_history_max_items(vault, clock.as_ref(), max);
    }

    /// Cap entry-history byte size. `-1` means unlimited.
    pub fn set_history_max_size(&mut self, max: i64) {
        let Unlocked { vault, clock, .. } = &mut self.state;
        vault_ops::meta_settings::set_history_max_size(vault, clock.as_ref(), max);
    }

    /// Set how long to keep entry snapshots before the host client
    /// prunes them, in days.
    pub fn set_maintenance_history_days(&mut self, days: u32) {
        let Unlocked { vault, clock, .. } = &mut self.state;
        vault_ops::meta_settings::set_maintenance_history_days(vault, clock.as_ref(), days);
    }

    /// Set the recommended-master-key-change interval, in days.
    /// `-1` disables the recommendation.
    pub fn set_master_key_change_rec(&mut self, days: i64) {
        let Unlocked { vault, clock, .. } = &mut self.state;
        vault_ops::meta_settings::set_master_key_change_rec(vault, clock.as_ref(), days);
    }

    /// Set the forced-master-key-change interval, in days.
    /// `-1` disables the force policy.
    pub fn set_master_key_change_force(&mut self, days: i64) {
        let Unlocked { vault, clock, .. } = &mut self.state;
        vault_ops::meta_settings::set_master_key_change_force(vault, clock.as_ref(), days);
    }

    /// Stamp [`crate::model::Meta::settings_changed`] from the
    /// injected clock via [`vault_ops::meta_settings::stamp_settings_changed`].
    /// Thin wrapper retained for the still-in-place verbs (e.g.
    /// `find_or_create_recycle_bin`) that stamp settings directly.
    fn stamp_settings_changed(&mut self) {
        let Unlocked { vault, clock, .. } = &mut self.state;
        vault_ops::meta_settings::stamp_settings_changed(vault, clock.as_ref());
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

        match &mut self.state.outer_header.version_fields {
            VersionFields::V3 { transform_seed, .. } => {
                // KDBX3 keeps the AES-KDF transform seed in the outer
                // header. Refresh it; rounds are unchanged.
                let mut new_transform_seed = [0u8; 32];
                getrandom::fill(&mut new_transform_seed)
                    .map_err(|_| Error::Crypto(CryptoError::Decrypt))?;
                *transform_seed = TransformSeed(new_transform_seed);
            }
            VersionFields::V4 { kdf_parameters, .. } => {
                // KDBX4 keeps KDF parameters as a VarDictionary blob.
                // Reparse, replace the `S` value (Argon2 salt or
                // AES-KDF seed — same key in both shapes), reserialise.
                let mut dict = VarDictionary::parse(kdf_parameters)
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
                *kdf_parameters = dict
                    .write()
                    .map_err(|_| FormatError::MalformedHeader("failed to encode KDF parameters"))?;
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

    let ciphertext: Vec<u8> = match header.version() {
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
        match &header.version_fields {
            VersionFields::V3 {
                stream_start_bytes,
                inner_stream_algorithm,
                protected_stream_key,
                ..
            } => {
                if plaintext.len() < 32 {
                    return Err(CryptoError::Decrypt.into());
                }
                let (got_sentinel, rest) = plaintext.split_at(32);
                // Constant-time compare avoids leaking the "password correct,
                // but ciphertext after this point is garbled" partial oracle.
                if got_sentinel.ct_eq(&stream_start_bytes.0).unwrap_u8() == 0 {
                    return Err(CryptoError::Decrypt.into());
                }
                let framed = read_hashed_block_stream(rest).map_err(FormatError::from)?;
                let decompressed = decompress(header.compression, &framed)
                    .map_err(|_| FormatError::MalformedHeader("payload failed to decompress"))?;
                // KDBX3 quirk: the inner-stream key on disk is hashed with
                // SHA-256 before it becomes the Salsa20 key. KDBX4 skips
                // this step (ChaCha20's SHA-512 derivation in
                // InnerStreamCipher::new does the equivalent internally).
                let hashed = Sha256::digest(protected_stream_key.0);
                (decompressed, *inner_stream_algorithm, hashed.to_vec())
            }
            VersionFields::V4 { .. } => {
                let decompressed = decompress(header.compression, &plaintext)
                    .map_err(|_| FormatError::MalformedHeader("payload failed to decompress"))?;
                let inner = InnerHeader::parse(&decompressed)
                    .map_err(|_| FormatError::MalformedHeader("malformed inner header"))?;
                let xml = decompressed[inner.consumed_bytes..].to_vec();
                // The inner-stream cipher is reserved for XML
                // `<Value Protected="True">` payloads. KDBX4 inner-header
                // binaries are *not* part of the keystream — they ride on
                // disk as plaintext, with their per-binary flag byte (`0x01`
                // for "protected") acting only as an in-memory hint to
                // downstream consumers. Earlier revisions of this loop
                // mistakenly XOR-ed the binaries' bytes through the cipher,
                // which both corrupted the attachment payloads and shifted
                // the keystream offset for every subsequent protected XML
                // value. See kdbxweb's `readBinary` and KeePassXC's
                // `Kdbx4Reader::readInnerHeaderField` for the same
                // convention.
                let mut cipher =
                    InnerStreamCipher::new(inner.inner_stream_algorithm, &inner.inner_stream_key)
                        .map_err(|_| CryptoError::Decrypt)?;
                for inner_bin in inner.binaries {
                    let protected = inner_bin.is_protected();
                    let data = inner_bin.data;
                    binaries.push(Binary { data, protected });
                }
                let mut vault = decode_vault_with_cipher(&xml, &mut cipher)?;
                reject_kdbx4_inner_xml_binaries_pool(&vault)?;
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
                    protector: None,
                    protected_fields: ProtectedFieldMap::new(),
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
        protector: None,
        protected_fields: ProtectedFieldMap::new(),
    })
}

// ---------------------------------------------------------------------------
// FieldProtector plumbing — wrap on unlock, unwrap on save / reveal.
// ---------------------------------------------------------------------------

/// Walk every entry in `vault` (and each entry's history snapshots),
/// wrap its protected-field plaintext via `protector`, blank the
/// matching `String` slot on the model, and return the resulting
/// [`ProtectedFieldMap`].
///
/// Called from [`Kdbx::<HeaderRead>::unlock_with_protector`] after the
/// inner-stream cipher has decrypted the protected XML values; this
/// pass is what makes "no plaintext in `Entry`" true for a vault that
/// was unlocked with a protector.
///
/// Empty plaintext is left as-is — wrapping an empty `String` is a
/// no-op round-trip and would just consume protector cycles. Reveal
/// returns the empty `String` straight from the model in that case.
fn wrap_vault_protected_fields(
    vault: &mut Vault,
    protector: &dyn FieldProtector,
) -> Result<ProtectedFieldMap, ProtectorError> {
    // One key fetch per bulk pass. Key is zeroed when this function returns.
    let key = protector.acquire_session_key()?;
    let mut map = ProtectedFieldMap::new();
    for entry in vault.iter_entries_mut() {
        let wrapped = wrap_entry_with_key(entry, &key)?;
        map.insert(entry.id, wrapped);
    }
    Ok(map)
}

/// Wrap an entry's protected fields against a pre-acquired session key.
/// Used by both the bulk pass and the entry editor's per-edit re-wrap
/// (which acquires its own key once per edit).
fn wrap_entry_with_key(
    entry: &mut Entry,
    key: &SessionKey,
) -> Result<ProtectedFields, ProtectorError> {
    let mut out = ProtectedFields {
        password: wrap_string_in_place_with_key(&mut entry.password, key)?,
        ..ProtectedFields::default()
    };
    for cf in &mut entry.custom_fields {
        if cf.protected {
            if let Some(b) = wrap_string_in_place_with_key(&mut cf.value, key)? {
                out.custom_fields.insert(cf.key.clone(), b);
            }
        }
    }
    for snap in &mut entry.history {
        // History snapshots are full Entry values with their own
        // protected-field state; recurse, but they themselves never
        // nest further history (per `Entry::history` doc).
        let snap_wrapped = wrap_entry_with_key(snap, key)?;
        out.history.push(snap_wrapped);
    }
    Ok(out)
}

/// Seal `value`'s bytes under `key` and replace the contents with an
/// empty string. Returns `None` if the input is already empty (no
/// wrap performed — saves a protector round-trip on entries with no
/// password).
fn wrap_string_in_place_with_key(
    value: &mut String,
    key: &SessionKey,
) -> Result<Option<Vec<u8>>, ProtectorError> {
    if value.is_empty() {
        return Ok(None);
    }
    let bytes = seal_with_key(key, value.as_bytes())?;
    value.clear();
    Ok(Some(bytes))
}

/// Walk `vault` and restore plaintext on every protected field by
/// looking up the wrapped bytes in `map` and opening them under a
/// session key acquired once for the pass.
///
/// Mirror of [`wrap_vault_protected_fields`], used by the save
/// pipeline on a local clone of the vault so the canonical
/// [`Unlocked::vault`] state stays wrapped across the save.
fn unwrap_vault_protected_fields(
    vault: &mut Vault,
    map: &ProtectedFieldMap,
    protector: &dyn FieldProtector,
) -> Result<(), ProtectorError> {
    let key = protector.acquire_session_key()?;
    for entry in vault.iter_entries_mut() {
        if let Some(record) = map.get(&entry.id) {
            unwrap_entry_with_key(entry, record, &key)?;
        }
    }
    Ok(())
}

fn unwrap_entry_with_key(
    entry: &mut Entry,
    record: &ProtectedFields,
    key: &SessionKey,
) -> Result<(), ProtectorError> {
    if let Some(b) = &record.password {
        entry.password = decode_wrapped_with_key(b, key)?;
    }
    for cf in &mut entry.custom_fields {
        if cf.protected {
            if let Some(b) = record.custom_fields.get(&cf.key) {
                cf.value = decode_wrapped_with_key(b, key)?;
            }
        }
    }
    // History snapshots align by position with the record's history.
    // Skip silently if lengths diverge: that can happen mid-edit before
    // a save (the entry editor records new history while the protector
    // map hasn't been refreshed) — encoder writes whatever the entry
    // currently holds, which is the same shape as the no-protector
    // path.
    for (snap, snap_record) in entry.history.iter_mut().zip(record.history.iter()) {
        unwrap_entry_with_key(snap, snap_record, key)?;
    }
    Ok(())
}

fn decode_wrapped_with_key(wrapped: &[u8], key: &SessionKey) -> Result<String, ProtectorError> {
    let bytes = open_with_key(key, wrapped)?;
    String::from_utf8(bytes)
        .map_err(|e| ProtectorError::Open(format!("opened bytes are not valid UTF-8: {e}")))
}

// ---------------------------------------------------------------------------
// Save pipeline — the byte-level inverse of do_unlock.
// ---------------------------------------------------------------------------

fn do_save(signature: FileSignature, version: Version, state: &Unlocked) -> Result<Vec<u8>, Error> {
    // Save-time GC mutates a local clone of the vault so the
    // caller-visible in-memory state stays byte-stable across a save.
    // The binary-pool GC also runs eagerly inside the mutations that
    // can orphan a binary (`edit_entry`/`detach`, `delete_entry`,
    // `delete_group`, `restore_history`); the call here is
    // defence-in-depth so a future mutation that forgets the post-pass
    // can't leak orphan attachment bytes to disk. The icon-pool GC
    // runs only here — see `gc_custom_icons_pool` for why icons skip
    // the per-mutation rhythm.
    let mut vault = state.vault.clone();
    gc_binaries_pool(&mut vault);
    gc_custom_icons_pool(&mut vault);
    // Unwrap protected fields back into the cloned vault before the
    // encoder runs. The canonical `state.vault` keeps its wrapped /
    // empty-plaintext shape, so the in-memory posture is unaffected
    // by the save round-trip. No-op when no protector is configured.
    if let Some(protector) = state.protector.as_ref() {
        unwrap_vault_protected_fields(&mut vault, &state.protected_fields, protector.as_ref())?;
    }
    match version {
        Version::V3 => do_save_v3(signature, state, &vault),
        Version::V4 => do_save_v4(signature, state, &vault),
    }
}

/// Reject a KDBX4 unlock when the inner XML carries
/// `<Meta><Binaries>`.
///
/// KDBX4 puts attachment payloads in the inner header, not the
/// XML — but the decoder is permissive enough to populate
/// `vault.binaries` from a stray `<Binaries>` block. Letting that
/// through would mean the inner-header pool silently overwrites
/// the XML pool on the next line, and any entries the XML pool
/// carried would just vanish. Surface the malformation explicitly
/// so it's loud instead of lossy.
///
/// Defence-in-depth against the bug shape the audit was kicked off
/// by — KDBX3 binary-pool clobber masked by a permissive test gate.
fn reject_kdbx4_inner_xml_binaries_pool(vault: &Vault) -> Result<(), Error> {
    if !vault.binaries.is_empty() {
        return Err(Error::Format(FormatError::MalformedHeader(
            "KDBX4 inner XML carries <Meta><Binaries>; binaries belong in the inner header on V4",
        )));
    }
    Ok(())
}

/// Build a per-save copy of the outer header with a freshly generated
/// `encryption_iv` (and `master_seed`).
///
/// `save_to_bytes` is `&self`, so we don't mutate the unlocked state —
/// each save just generates a fresh nonce locally. The point is to
/// prevent (key, IV) reuse across successive saves under the same
/// unlocked composite key:
///
/// - **ChaCha20** (KDBX4) is the catastrophic case: reusing the same
///   (key, nonce) pair across two distinct plaintexts directly leaks
///   `plaintext_a XOR plaintext_b`. Without a fresh nonce per save,
///   any caller that does `unlock → edit → save → edit → save` hands
///   an attacker who captures both files the XOR difference of the
///   two payloads.
/// - **AES-256-CBC** (KDBX3 + KDBX4) is the lesser case: it stays
///   semantically secure under reused IVs in the sense that no
///   plaintext byte leaks, but identical leading plaintext blocks
///   produce identical leading ciphertext blocks, which exposes a
///   change-detection oracle.
///
/// We also rotate `master_seed` for defence in depth — it costs ~32
/// bytes of CSPRNG output and means a captured prior file can't be
/// decrypted even given the new cipher_key (their `cipher_key =
/// SHA-256(master_seed || transformed_key)` differs). The cached
/// `transformed_key` itself is unaffected (it depends on the KDF
/// salt, not on master_seed), so this stays free of any second KDF
/// pass.
fn fresh_save_header(header: &OuterHeader) -> Result<OuterHeader, Error> {
    let mut new_iv = vec![0u8; header.encryption_iv.0.len()];
    getrandom::fill(&mut new_iv).map_err(|_| Error::Crypto(CryptoError::Decrypt))?;
    let mut new_master_seed = [0u8; 32];
    getrandom::fill(&mut new_master_seed).map_err(|_| Error::Crypto(CryptoError::Decrypt))?;
    let mut out = header.clone();
    out.encryption_iv = EncryptionIv(new_iv);
    out.master_seed = MasterSeed(new_master_seed);
    Ok(out)
}

fn do_save_v4(signature: FileSignature, state: &Unlocked, vault: &Vault) -> Result<Vec<u8>, Error> {
    let header_owned = fresh_save_header(&state.outer_header)?;
    let header = &header_owned;
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
        // KDBX4 inner-header binaries are written as plaintext on disk;
        // the `protected` flag is an in-memory hint for consumers, not
        // an instruction to XOR with the inner-stream keystream. The
        // inner-stream cipher is reserved exclusively for XML
        // `<Value Protected="True">` payloads — see kdbxweb's
        // `readBinary`/`writeBinary` and KeePassXC's `Kdbx4Reader`/
        // `Kdbx4Writer` for the same convention.
        inner_binaries.push(InnerBinary {
            flags,
            data: b.data.clone(),
        });
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

    // --- XML encode with the inner-stream cipher ------------------------
    // Inner-header binaries above did not advance the cipher (they ride as
    // plaintext on disk), so the keystream starts at offset 0 here — the
    // same offset the reader will see for the first protected `<Value>`.
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
    let header_owned = fresh_save_header(&state.outer_header)?;
    let header = &header_owned;
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

    let VersionFields::V3 {
        stream_start_bytes, ..
    } = &header.version_fields
    else {
        return Err(Error::Format(FormatError::MalformedHeader(
            "KDBX3 save_to_bytes requires a KDBX3 outer header",
        )));
    };

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
        let password: String = serde_json::from_str::<serde_json::Value>(&sidecar_text)
            .unwrap()
            .get("master_password")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .unwrap();
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
        let password: String = serde_json::from_str::<serde_json::Value>(&sidecar_text)
            .unwrap()
            .get("master_password")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .unwrap();
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
