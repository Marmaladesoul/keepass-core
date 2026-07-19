//! Field-protector **read** path — recover protected-field plaintext on
//! demand without mutating the vault or the saved bytes.
//!
//! Mirrors [`import_export`](crate::vault_ops::import_export): every verb
//! is a read-only free fn over a `&Vault` (plus the injected field
//! protector and its side-table), and [`Kdbx<Unlocked>`](crate::kdbx::Kdbx)
//! keeps a thin delegating wrapper for each public one
//! ([`vault_with_unwrapped_protected`], [`reveal_password`],
//! [`reveal_custom_field`]) so the public API is byte-for-byte unchanged.
//!
//! The protector and its side-table are injected the same way the clock
//! is elsewhere: `protector: Option<&dyn FieldProtector>` and
//! `protected_fields: &ProtectedFieldMap`. Both are threaded in from the
//! [`Unlocked`](crate::kdbx::Kdbx) state by the wrappers rather than
//! living on the [`Vault`] data type.
//!
//! This module owns only the *policy* of choosing plaintext-vs-decode; the
//! wrap/unwrap-with-key primitives stay in [`crate::kdbx`]
//! ([`unwrap_vault_protected_fields`](crate::kdbx::unwrap_vault_protected_fields)
//! and [`decode_wrapped_with_key`](crate::kdbx::decode_wrapped_with_key)),
//! which these verbs call across a deliberate, minimal back-reference.
//!
//! Both paths preserve the pre-protector contract exactly:
//! - **No protector** (`protector = None`): the stored model value is
//!   returned verbatim — protected fields were never wrapped, so they
//!   already hold plaintext.
//! - **Protector configured** (`protector = Some`): a session key is
//!   acquired and the wrapped bytes are decoded; a non-protected custom
//!   field is still returned verbatim (it was never wrapped), and an
//!   entry/field with no recorded wrapped bytes reads back as the empty
//!   string.

use crate::error::Error;
use crate::kdbx::{ProtectedFieldMap, decode_wrapped_with_key, unwrap_vault_protected_fields};
use crate::model::{EntryId, ModelError, Vault};
use crate::protector::FieldProtector;

/// Free-fn core of
/// [`Kdbx::vault_with_unwrapped_protected`](crate::kdbx::Kdbx::vault_with_unwrapped_protected);
/// see the wrapper for the full contract. Returns a clone of `vault` with
/// every protected field's plaintext spliced back in.
///
/// When `protector` is `None` the clone is returned verbatim — `vault`
/// already carries plaintext on that path.
///
/// # Errors
///
/// Returns [`Error::Protector`] if the configured protector's `unwrap`
/// rejects any wrapped blob or produces non-UTF-8 output.
pub(crate) fn vault_with_unwrapped_protected(
    vault: &Vault,
    protector: Option<&dyn FieldProtector>,
    protected_fields: &ProtectedFieldMap,
) -> Result<Vault, Error> {
    let mut vault = vault.clone();
    if let Some(protector) = protector {
        unwrap_vault_protected_fields(&mut vault, protected_fields, protector)?;
    }
    Ok(vault)
}

/// Free-fn core of
/// [`Kdbx::reveal_password`](crate::kdbx::Kdbx::reveal_password); see the
/// wrapper for the full contract.
///
/// # Errors
///
/// Returns [`ModelError::EntryNotFound`] if no entry matches `id`, or
/// [`Error::Protector`] if the protector fails or the wrapped bytes can't
/// be opened / produce non-UTF-8 output.
pub(crate) fn reveal_password(
    vault: &Vault,
    protector: Option<&dyn FieldProtector>,
    protected_fields: &ProtectedFieldMap,
    id: EntryId,
) -> Result<String, Error> {
    let entry = vault.root.entry(id).ok_or(ModelError::EntryNotFound(id))?;
    match (protector, protected_fields.get(&id)) {
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

/// Free-fn core of
/// [`Kdbx::reveal_custom_field`](crate::kdbx::Kdbx::reveal_custom_field);
/// see the wrapper for the full contract.
///
/// # Errors
///
/// Returns [`ModelError::EntryNotFound`] if no entry matches `id`, or
/// [`Error::Protector`] on protector failure or non-UTF-8 output.
pub(crate) fn reveal_custom_field(
    vault: &Vault,
    protector: Option<&dyn FieldProtector>,
    protected_fields: &ProtectedFieldMap,
    id: EntryId,
    key: &str,
) -> Result<Option<String>, Error> {
    let entry = vault.root.entry(id).ok_or(ModelError::EntryNotFound(id))?;
    let Some(cf) = entry.custom_fields.iter().find(|c| c.key == key) else {
        return Ok(None);
    };
    if !cf.protected {
        return Ok(Some(cf.value.clone()));
    }
    match (protector, protected_fields.get(&id)) {
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
