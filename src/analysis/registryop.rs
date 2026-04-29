//! Registry entries classified by the install-time mutation they
//! describe.
//!
//! `[Registry]` entries default to "write a value", but the
//! `Flags:` directive can promote them to a key/value deletion
//! instead. [`InnoInstaller::registry_ops`](crate::InnoInstaller::registry_ops)
//! walks `inst.registry_entries()` and tags each entry with a
//! [`RegistryOpKind`] derived from those flags so analyst code can
//! filter on the operation without re-reading the bitset itself.
//!
//! For uninstall-time effects (`UninsDeleteValue`,
//! `UninsDeleteEntireKey`, `UninsClearValue`,
//! `UninsDeleteEntireKeyIfEmpty`) inspect the underlying entry's
//! `flags` set directly via [`RegistryOp::source`].

use crate::records::registry::{RegistryEntry, RegistryFlag};

/// Coarse classification of an `[Registry]` entry's install-time
/// mutation. Mirrors the Inno runtime's `Setup.RegistryFunc.pas`
/// dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryOpKind {
    /// Writes a value unconditionally (the default behavior when
    /// no `Flags:` modifier overrides it). Pairs with
    /// [`RegistryEntry::value_type`] for the value-type detail.
    Write,
    /// Writes a value only if the named value did not previously
    /// exist (`Flags: createvalueifdoesntexist`).
    WriteIfMissing,
    /// Deletes the named value rather than writing it
    /// (`Flags: deletevalue`). [`RegistryEntry::value_name`] is
    /// the value to delete.
    DeleteValue,
    /// Deletes the entire key rather than writing it
    /// (`Flags: deletekey`). [`RegistryEntry::value_name`] is
    /// ignored.
    DeleteKey,
}

/// A single classified `[Registry]` operation.
///
/// Borrows from the underlying [`RegistryEntry`]; that entry
/// carries every Inno-specific detail (hive, value type, raw
/// value bytes, conditions, uninstall-time flags) for callers
/// that need full fidelity.
#[derive(Clone, Copy, Debug)]
pub struct RegistryOp<'a> {
    /// Install-time effect category.
    pub kind: RegistryOpKind,
    /// Underlying parsed record.
    pub source: &'a RegistryEntry,
}

impl RegistryOp<'_> {
    fn classify(entry: &RegistryEntry) -> RegistryOpKind {
        // Order matters: `DeleteKey` and `DeleteValue` are
        // mutually exclusive at the .iss level but if both bits
        // are set on a malformed installer, prefer the broader
        // operation (DeleteKey).
        if entry.flags.contains(&RegistryFlag::DeleteKey) {
            RegistryOpKind::DeleteKey
        } else if entry.flags.contains(&RegistryFlag::DeleteValue) {
            RegistryOpKind::DeleteValue
        } else if entry
            .flags
            .contains(&RegistryFlag::CreateValueIfDoesntExist)
        {
            RegistryOpKind::WriteIfMissing
        } else {
            RegistryOpKind::Write
        }
    }
}

/// Iterator yielded by
/// [`InnoInstaller::registry_ops`](crate::InnoInstaller::registry_ops).
#[derive(Clone)]
pub struct RegistryOpIter<'a> {
    inner: std::slice::Iter<'a, RegistryEntry>,
}

impl<'a> RegistryOpIter<'a> {
    pub(crate) fn new(entries: &'a [RegistryEntry]) -> Self {
        Self {
            inner: entries.iter(),
        }
    }
}

impl<'a> Iterator for RegistryOpIter<'a> {
    type Item = RegistryOp<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let source = self.inner.next()?;
        Some(RegistryOp {
            kind: RegistryOp::classify(source),
            source,
        })
    }
}
