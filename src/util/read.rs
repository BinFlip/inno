//! Cursor-style reader over a byte slice with checked reads.
//!
//! Designed for parsing adversarial input under the crate's deny set
//! (no `[i]` indexing, no `unwrap`, no arithmetic side effects). Every
//! operation that could fail returns [`Error`] instead of panicking.

use crate::error::Error;

/// Forward-only cursor over a byte slice.
#[derive(Debug)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

// Some accessors are not exercised by every caller; suppress
// dead-code warnings rather than narrow the surface.
#[allow(dead_code)]
impl<'a> Reader<'a> {
    /// Wraps `buf` with the cursor positioned at offset 0.
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Wraps `buf` with the cursor positioned at the given offset.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] if `start` is past the end of `buf`.
    pub(crate) fn at(buf: &'a [u8], start: usize) -> Result<Self, Error> {
        if start > buf.len() {
            return Err(Error::Truncated { what: "Reader::at" });
        }
        Ok(Self { buf, pos: start })
    }

    /// Current byte offset into the underlying slice.
    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    /// Bytes still available beyond the cursor.
    pub(crate) fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Advances the cursor by `n` bytes without yielding them.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Overflow`] if `pos + n` overflows `usize`,
    /// [`Error::Truncated`] if it runs past the end of the buffer.
    pub(crate) fn skip(&mut self, n: usize, what: &'static str) -> Result<(), Error> {
        let new_pos = self.pos.checked_add(n).ok_or(Error::Overflow { what })?;
        if new_pos > self.buf.len() {
            return Err(Error::Truncated { what });
        }
        self.pos = new_pos;
        Ok(())
    }

    /// Yields the next `n` bytes as a borrowed sub-slice and advances
    /// the cursor.
    ///
    /// # Errors
    ///
    /// Same as [`Reader::skip`].
    pub(crate) fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], Error> {
        let new_pos = self.pos.checked_add(n).ok_or(Error::Overflow { what })?;
        let slice = self
            .buf
            .get(self.pos..new_pos)
            .ok_or(Error::Truncated { what })?;
        self.pos = new_pos;
        Ok(slice)
    }

    /// Reads an exactly-`N`-byte fixed-length array and advances the
    /// cursor.
    ///
    /// # Errors
    ///
    /// Same as [`Reader::skip`].
    pub(crate) fn array<const N: usize>(&mut self, what: &'static str) -> Result<[u8; N], Error> {
        let bytes = self.take(N, what)?;
        let mut out = [0u8; N];
        // bytes.len() == N is guaranteed by `take` returning the
        // requested length on success. copy_from_slice with matching
        // lengths cannot panic.
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Reads one unsigned byte.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] if the buffer is exhausted.
    pub(crate) fn u8(&mut self, what: &'static str) -> Result<u8, Error> {
        let b = self
            .buf
            .get(self.pos)
            .copied()
            .ok_or(Error::Truncated { what })?;
        self.pos = self.pos.saturating_add(1);
        Ok(b)
    }

    /// Reads a little-endian `u16` and advances 2 bytes.
    ///
    /// # Errors
    ///
    /// Same as [`Reader::skip`].
    pub(crate) fn u16_le(&mut self, what: &'static str) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.array::<2>(what)?))
    }

    /// Reads a little-endian `u32` and advances 4 bytes.
    ///
    /// # Errors
    ///
    /// Same as [`Reader::skip`].
    pub(crate) fn u32_le(&mut self, what: &'static str) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array::<4>(what)?))
    }

    /// Reads a little-endian `i32` and advances 4 bytes.
    ///
    /// # Errors
    ///
    /// Same as [`Reader::skip`].
    pub(crate) fn i32_le(&mut self, what: &'static str) -> Result<i32, Error> {
        Ok(i32::from_le_bytes(self.array::<4>(what)?))
    }

    /// Reads a little-endian `u64` and advances 8 bytes.
    ///
    /// # Errors
    ///
    /// Same as [`Reader::skip`].
    pub(crate) fn u64_le(&mut self, what: &'static str) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.array::<8>(what)?))
    }

    /// Reads a little-endian `i64` and advances 8 bytes.
    ///
    /// # Errors
    ///
    /// Same as [`Reader::skip`].
    pub(crate) fn i64_le(&mut self, what: &'static str) -> Result<i64, Error> {
        Ok(i64::from_le_bytes(self.array::<8>(what)?))
    }

    /// Reads a Pascal `set` / `flags` bitfield as raw bytes.
    ///
    /// Per `research-notes/11-fixed-tail.md` and innoextract's
    /// `stored_bitfield<Bits, PadBits>` (`research/src/util/storedenum.hpp:99`),
    /// Inno Setup encodes a `set` of `bit_count` flags as
    /// `ceil(bit_count / 8)` bytes, with one special case: when
    /// the result is exactly 3 bytes and `pad_to_4` is set (the
    /// non-16-bit build default), one trailing padding byte is
    /// consumed and dropped. The padding byte is **not** returned.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] / [`Error::Overflow`] if the
    /// requested run of bytes runs past the buffer.
    pub(crate) fn set_bytes(
        &mut self,
        bit_count: usize,
        pad_to_4: bool,
        what: &'static str,
    ) -> Result<Vec<u8>, Error> {
        let bytes_needed = bit_count
            .checked_add(7)
            .and_then(|n| n.checked_div(8))
            .ok_or(Error::Overflow { what })?;
        let primary = self.take(bytes_needed, what)?.to_vec();
        if bytes_needed == 3 && pad_to_4 {
            self.skip(1, what)?;
        }
        Ok(primary)
    }
}

/// Convenience: read a little-endian `u32` from a fixed offset of `buf`
/// without constructing a [`Reader`]. Used in narrow probes (e.g. PE
/// magic checks).
///
/// # Errors
///
/// Returns [`Error::Truncated`] / [`Error::Overflow`] on out-of-bounds.
pub(crate) fn u32_le_at(buf: &[u8], offset: usize, what: &'static str) -> Result<u32, Error> {
    let end = offset.checked_add(4).ok_or(Error::Overflow { what })?;
    let bytes = buf.get(offset..end).ok_or(Error::Truncated { what })?;
    let mut arr = [0u8; 4];
    arr.copy_from_slice(bytes);
    Ok(u32::from_le_bytes(arr))
}
