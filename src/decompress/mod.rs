//! Decompression layer.
//!
//! Handles the block stream around the compressed `setup-0` header:
//! a 9-byte outer header (≥ 4.0.9) followed by a sequence of 4 KiB
//! CRC32-prefixed sub-chunks. The un-prefixed sub-chunks concatenate
//! into a raw LZMA1 / Zlib / stored stream.
//!
//! The setup-1 chunk stream uses a different framing and lives in
//! the `extract::chunk` module.
//!
//! See `RESEARCH.md` §4 and
//! `research-notes/05-streams-and-compression.md` §"Block (setup-0)"
//! for the canonical format reference.

pub mod block;

pub use block::{BlockCompression, decompress_block};
