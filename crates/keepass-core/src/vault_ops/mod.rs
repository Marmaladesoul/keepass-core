//! Vault-operation verbs and helpers — the policy / CRUD layer.
//!
//! ## The seam
//!
//! ```text
//! kdbx.rs (typestate + crypto)  →  thin Kdbx<Unlocked> wrappers  →  vault_ops (policy/CRUD, free fns)  →  model (data)
//! ```
//!
//! [`crate::kdbx`] owns the typestate machine (`Sealed` / `HeaderRead` /
//! `Unlocked`) and the crypto pipelines (unlock, save, rekey, and the
//! field-protector wrap/unwrap layer). This module owns the
//! **policy / CRUD verbs**, expressed as free functions over a
//! `&mut Vault` (plus an injected `&dyn Clock` wherever a mutation
//! stamps timestamps). The verbs need collaborators — a [`Clock`], and
//! later a field protector and its side-table — that are deliberately
//! not part of the [`Vault`] data type, so an explicit free-fn signature
//! keeps each verb's dependency footprint visible at every call site.
//!
//! [`Kdbx<Unlocked>`](crate::kdbx::Kdbx) keeps a thin delegating wrapper
//! for every verb, so the public API is byte-for-byte unchanged: each
//! wrapper field-destructures its `Unlocked` state and forwards to the
//! free fn here. Pure helpers (the id / history / tombstone / binary /
//! icon machinery) live here too, re-exported from [`crate::kdbx`] so the
//! crypto code that still calls them (chiefly the save-time GC) compiles
//! unchanged.
//!
//! `vault_ops` depends on [`model`](crate::model); the dependency never
//! runs the other way.
//!
//! [`Clock`]: crate::model::Clock
//! [`Vault`]: crate::model::Vault

pub(crate) mod binaries;
pub(crate) mod entry_ops;
pub(crate) mod group_ops;
pub(crate) mod history;
pub(crate) mod icons;
pub(crate) mod ids;
pub(crate) mod meta_settings;
pub(crate) mod recycle;
pub(crate) mod tombstones;
