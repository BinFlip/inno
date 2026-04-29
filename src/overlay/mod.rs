//! PE-overlay-locator pipeline.
//!
//! Inno Setup payloads live inside a Windows PE executable. The
//! [`pe`] module walks the PE container and locates the
//! `SetupLdrOffsetTable` resource (id `11111`) for installers built
//! with Inno Setup 5.1.5+, and the legacy file-offset locator at
//! `0x30` for older installers. The [`offsettable`] module decodes
//! the resulting bytes into a typed [`OffsetTable`].
//!
//! See `RESEARCH.md` §2 and `research-notes/02-loader-and-version.md`
//! for the format reference.

pub mod offsettable;
pub mod pe;

pub use offsettable::{OffsetTable, OffsetTableSource, SetupLdrFamily};
