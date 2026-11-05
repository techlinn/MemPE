use crate::pe::image::read_u32;

const BYTE_TAG_SENTINEL: u8 = 0x80;
const WORD_TAG_BITS: u32 = 32;

pub(crate) trait Bits {
    fn bit(&mut self) -> Option<u32>;
    fn byte(&mut self) -> Option<u8>;

    fn gamma(&mut self) -> Option<u32> {
        let mut value = 1u32;
        loop {
            value = value.checked_mul(2)?.checked_add(self.bit()?)?;
            if self.bit()? == 0 {
                return Some(value);
            }
        }
    }

    fn number(&mut self, count: u32) -> Option<u32> {
        (0..count).try_fold(0u32, |value, _| {
            value.checked_mul(2)?.checked_add(self.bit()?)
        })
    }
}

impl<T: Bits + ?Sized> Bits for &mut T {
    fn bit(&mut self) -> Option<u32> {
        (**self).bit()
    }

    fn byte(&mut self) -> Option<u8> {
        (**self).byte()
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    next: usize,
}

impl Cursor<'_> {
    fn byte(&mut self) -> Option<u8> {
        let byte = *self.data.get(self.next)?;
        self.next += 1;
        Some(byte)
    }

    fn dword(&mut self) -> Option<u32> {
        let value = read_u32(self.data, self.next).ok()?;
        self.next += 4;
        Some(value)
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
    fn bit(&mut self) -> Option<u32> {
        let mut bit = u32::from(self.tag >> 7);
        self.tag <<= 1;

        if self.tag == 0 {
            let byte = self.byte()?;
            bit = u32::from(byte >> 7);
            self.tag = (byte << 1) | 1; // the sentinel that just left marks the refill
        }

        Some(bit)
    }

    fn byte(&mut self) -> Option<u8> {
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
    fn bit(&mut self) -> Option<u32> {
        if self.left == 0 {
            self.buffer = self.cursor.dword()?;
            self.left = WORD_TAG_BITS;
        }

        self.left -= 1;
        Some((self.buffer >> self.left) & 1)
    }

    fn byte(&mut self) -> Option<u8> {
        self.cursor.byte()
    }
}
