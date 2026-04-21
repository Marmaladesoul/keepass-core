//! # keepass-merge
//!
//! Three-way merge logic for KeePass (KDBX) databases. Detects conflicts
//! between an in-memory vault and an updated version on disk, auto-merges safe
//! non-conflicting changes, and surfaces conflicting changes for the caller to
//! resolve.
//!
//! This crate exists separately from [`keepass_core`] because merge is a
//! distinct concern with its own test surface, and not every consumer of
//! `keepass-core` needs it (e.g. a read-only viewer or a format converter).
//!
//! Implementation pending.

#![doc(html_no_source)]
