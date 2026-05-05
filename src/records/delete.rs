//! `TSetupDeleteEntry` — `[InstallDelete]` / `[UninstallDelete]`
//! entry. The same struct is reused for both directives.
//!
//! Pascal layout (`is-6_4_1:Projects/Src/Shared.Struct.pas`):
//!
//! ```text
//! TSetupDeleteEntry = packed record
//!     Name: AnsiString;
//!     [ItemConditions]
//!     [WindowsVersionRange]
//!     DeleteType: TSetupDeleteType;   // u8 enum
//! end;
//! ```
//!
//! Reader reference: `research/src/setup/delete.cpp`.

use crate::{
    error::Error,
    records::item::ItemBase,
    util::{encoding::read_setup_string, read::Reader},
    version::Version,
};

/// `TSetupDeleteType` — what the entry deletes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeleteTargetType {
    /// `dtFiles` — file glob (no recursion).
    Files,
    /// `dtFilesAndSubdirs` — file glob + recurse subdirectories.
    FilesAndSubdirs,
    /// `dtDirIfEmpty` — directory, only if empty.
    DirIfEmpty,
}

stable_name_enum!(DeleteTargetType, {
    Self::Files => "files",
    Self::FilesAndSubdirs => "files_and_subdirs",
    Self::DirIfEmpty => "dir_if_empty",
});

/// Parsed `TSetupDeleteEntry`.
#[derive(Clone, Debug)]
pub struct DeleteEntry {
    /// `Name:` directive — file path / glob to delete (with Inno
    /// constants like `{app}` unresolved).
    pub name: String,
    /// Shared conditions + Windows version range.
    pub item: ItemBase,
    /// Decoded `DeleteType`.
    pub target_type: Option<DeleteTargetType>,
    /// Raw target-type byte.
    pub target_type_raw: u8,
}

impl DeleteEntry {
    /// Reads one `TSetupDeleteEntry`.
    ///
    /// # Errors
    ///
    /// String / truncation / overflow per [`Error`].
    pub(crate) fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        let name = read_setup_string(reader, version, "Delete.Name")?;
        let item = ItemBase::read(reader, version)?;
        let target_type_raw = reader.u8("Delete.Type")?;
        Ok(Self {
            name,
            item,
            target_type: decode_delete_type(target_type_raw),
            target_type_raw,
        })
    }
}

fn decode_delete_type(b: u8) -> Option<DeleteTargetType> {
    match b {
        0 => Some(DeleteTargetType::Files),
        1 => Some(DeleteTargetType::FilesAndSubdirs),
        2 => Some(DeleteTargetType::DirIfEmpty),
        _ => None,
    }
}
