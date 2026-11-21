use super::{DecodeError, Decoded};
use crate::pe::bytes::read_u32;

const BYTE_TAG_SENTINEL: u8 = 0x80;
const WORD_TAG_BITS: u32 = 32;

pub(crate) trait Bits {
    fn bit(&mut self) -> Decoded<u32>;
    fn byte(&mut self) -> Decoded<u8>;

    fn gamma(&mut self) -> Decoded<u32> {
        self.gamma_ending(0)
    }

    fn gamma_ending(&mut self, stop: u32) -> Decoded<u32> {
        let mut value = 1u32;
        loop {
            value = value.checked_mul(2).ok_or(DecodeError::Corrupt)? | self.bit()?;
            if self.bit()? == stop {
                return Ok(value);
            }
        }
    }

    fn number(&mut self, count: u32) -> Decoded<u32> {
        (0..count).try_fold(0u32, |value, _| {
            let doubled = value.checked_mul(2).ok_or(DecodeError::Corrupt)?;
            Ok(doubled | self.bit()?)
        })
    }
}

impl<T: Bits + ?Sized> Bits for &mut T {
    fn bit(&mut self) -> Decoded<u32> {
        (**self).bit()
    }

    fn byte(&mut self) -> Decoded<u8> {
        (**self).byte()
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    next: usize,
}

impl Cursor<'_> {
    fn byte(&mut self) -> Decoded<u8> {
        let byte = *self.data.get(self.next).ok_or(DecodeError::Truncated)?;
        self.next += 1;
        Ok(byte)
    }

    fn dword(&mut self) -> Decoded<u32> {
        let value = read_u32(self.data, self.next).map_err(|_| DecodeError::Truncated)?;
        self.next += 4;
        Ok(value)
    }
}

pub(crate) struct ByteTags<'a> {
    cursor: Cursor<'a>,
    tag: u8,
}

impl<'a> ByteTags<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self {
            cursor: Cursor { data, next: 0 },
            tag: BYTE_TAG_SENTINEL,
        }
    }

    pub(crate) fn position(&self) -> usize {
        self.cursor.next
    }
}

impl Bits for ByteTags<'_> {
    fn bit(&mut self) -> Decoded<u32> {
        let mut bit = u32::from(self.tag >> 7);
        self.tag <<= 1;

        if self.tag == 0 {
            let byte = self.byte()?;
            bit = u32::from(byte >> 7);
            self.tag = (byte << 1) | 1; // sentinel bit marks the refill
        }

        Ok(bit)
    }

    fn byte(&mut self) -> Decoded<u8> {
        self.cursor.byte()
    }
}

pub(crate) struct WordTags<'a> {
    cursor: Cursor<'a>,
    buffer: u32,
    left: u32,
}

impl<'a> WordTags<'a> {
    pub(crate) fn new(data: &'a [u8], start: usize) -> Self {
        Self {
            cursor: Cursor { data, next: start },
            buffer: 0,
            left: 0,
        }
    }
}

impl Bits for WordTags<'_> {
    fn bit(&mut self) -> Decoded<u32> {
        if self.left == 0 {
            self.buffer = self.cursor.dword()?;
            self.left = WORD_TAG_BITS;
        }

        self.left -= 1;
        Ok((self.buffer >> self.left) & 1)
    }

    fn byte(&mut self) -> Decoded<u8> {
        self.cursor.byte()
    }
}
