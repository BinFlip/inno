//! Parse and inspect Inno Setup installer binaries.
//!
//! This crate provides typed access to the internal structures of an
//! [Inno Setup](https://jrsoftware.org/isinfo.php) installer executable,
//! from the PE loader stub through the compressed setup header down to
//! individual records and embedded files.
//!
//! Format research is tracked in `RESEARCH.md` at the crate root and is
//! the source of truth for what each layer of the parser implements.
//!
//! # Stable Identifiers
//!
//! Public discriminator enums expose stable [`core::fmt::Display`]
//! strings, and most also expose `as_str()`. Consumers may persist
//! those strings in databases and compare them across crate releases.
//! New variants on `#[non_exhaustive]` enums are added in minor-version
//! releases; once a variant's display string is published, that string
//! is a compatibility surface and will not be renamed.
//!
//! # Architecture
//!
//! The crate is organized in layers that mirror the on-disk format:
//!
//! - **PE overlay detection** ([`overlay`]): Locates the Inno Setup loader
//!   table (`SetupLdr`) and the setup payload appended after the PE
//!   sections.
//! - **Decompression** ([`decompress`]): Handles `zlib`, LZMA, and LZMA2
//!   decompression of the setup header and data streams.
//! - **Low-level structures** ([`header`], [`records`]): View types for
//!   each structure in the setup header (`TSetupHeader`, file/registry/
//!   ini/run records, language tables, Pascal script, and the file
//!   location table).
//! - **High-level API** ([`InnoInstaller`]): Ties everything together
//!   into a convenient exploration interface for analysis use cases.

// The `missing_docs`, `unsafe_code`, `clippy::unwrap_used`,
// `clippy::expect_used`, `clippy::panic`,
// `clippy::arithmetic_side_effects`, and `clippy::indexing_slicing` lints
// are declared in `Cargo.toml` under `[lints]` so they enforce on every
// build regardless of the consuming workspace. innospect is used in
// malware-analysis pipelines where every input byte is adversarial and
// the parser must not panic.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing
    )
)]

macro_rules! stable_name_enum {
    ($ty:ty, { $($pat:pat => $name:literal),+ $(,)? }) => {
        impl $ty {
            /// Returns this value's stable identifier.
            #[must_use]
            pub fn as_str(&self) -> &'static str {
                match self {
                    $($pat => $name,)+
                }
            }
        }

        impl core::fmt::Display for $ty {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

macro_rules! stable_flag_enum {
    ($ty:ty, { $($variant:ident => $name:literal),+ $(,)? }) => {
        stable_name_enum!($ty, { $(Self::$variant => $name,)+ });

        impl $ty {
            /// Canonical storage order for this flag enum.
            pub const ORDER: &'static [Self] = &[$(Self::$variant,)+];

            /// Canonical stable-name order for this flag enum.
            pub const NAME_ORDER: &'static [&'static str] = &[$($name,)+];

            /// Returns this flag's canonical bit position.
            #[must_use]
            pub fn bit(self) -> u64 {
                let shift = Self::ORDER
                    .iter()
                    .position(|flag| *flag == self)
                    .and_then(|idx| u32::try_from(idx).ok());
                shift.and_then(|idx| 1_u64.checked_shl(idx)).unwrap_or(0)
            }

            /// Converts a set of flags into the canonical bitmask.
            #[must_use]
            pub fn set_to_bits(set: &std::collections::HashSet<Self>) -> u64 {
                set.iter().fold(0_u64, |acc, flag| acc | flag.bit())
            }
        }
    };
}

pub mod analysis;
pub mod decompress;
pub mod error;
pub mod extract;
pub mod header;
pub mod installer;
pub mod overlay;
pub mod records;
pub mod version;

/// Re-export of the `pascalscript` crate so existing
/// `innospect::pascalscript::*` paths resolve through `innospect`. The
/// parser itself is the standalone
/// [`pascalscript`](https://github.com/BinFlip/pascalscript-rs)
/// crate; this re-export is for caller convenience.
pub use ::pascalscript;

mod crypto;
mod util;

pub use error::Error;
pub use extract::FileReader;
pub use header::{
    Architecture, AutoNoYes, CompressMethod, EntryCounts, HeaderAnsi, HeaderOption, HeaderString,
    HeaderTail, ImageAlphaFormat, LanguageDetectionMethod, PrivilegesRequired,
    PrivilegesRequiredOverride, SetupHeader, UninstallLogMode, WizardStyle, YesNoAuto,
};
pub use installer::{Compression, EncryptionInfo, EncryptionMode, InnoInstaller};
pub use overlay::{
    OffsetTable, OffsetTableSource, SetupLdrFamily, pe::LocatorMode as PeLocatorMode,
};
pub use records::{
    component::{ComponentEntry, ComponentFlag},
    dataentry::{DataChecksum, DataEntry, DataFlag, SignMode},
    delete::{DeleteEntry, DeleteTargetType},
    directory::{DirectoryEntry, DirectoryFlag},
    file::{FileEntry, FileEntryType, FileFlag, FileVerification, FileVerificationKind},
    icon::{CloseOnExit, IconEntry, IconFlag},
    ini::{IniEntry, IniFlag},
    isssigkey::ISSigKeyEntry,
    language::{LanguageCodepage, LanguageEntry},
    message::MessageEntry,
    permission::PermissionEntry,
    registry::{RegistryEntry, RegistryFlag, RegistryHive, RegistryValueType},
    run::{RunEntry, RunFlag, RunWait},
    task::{TaskEntry, TaskFlag},
    type_::{SetupTypeKind, TypeEntry},
    windows::Bitness,
};
pub use version::{Variant, Version, VersionFlags};

// Thread-safety guarantee: InnoInstaller borrows from a `&[u8]` input
// buffer, holds no interior mutability, and contains no raw pointers
// or `Cell`/`RefCell`. It is therefore both `Send` and `Sync`. This
// static assertion makes the guarantee a compile-time invariant: a
// future change that adds a non-Send/non-Sync field will break the
// build here, not silently at a downstream `.await` point.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<InnoInstaller<'static>>();
};
