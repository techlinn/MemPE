use crate::pe::image::read_u32;

const END_MARKER: u32 = u32::MAX;
const REPEAT_OFFSET: u32 = 2;
const OFFSET_BIAS: u32 = 3;
const NRV2B_FAR: u32 = 0xD00; // matches further back than this are one byte longer
const NRV2DE_FAR: u32 = 0x500;

#[derive(Clone, Copy)]
pub(super) enum Variant {
    B,
    D,
    E,
}

struct Bits<'a> {
    data: &'a [u8],
    next: usize,
    buffer: u32,
    left: u32,
}

impl Bits<'_> {
    fn byte(&mut self) -> Option<u8> {
        let byte = *self.data.get(self.next)?;
        self.next += 1;
        Some(byte)
    }

    fn bit(&mut self) -> Option<u32> {
        if self.left == 0 {
            self.buffer = read_u32(self.data, self.next).ok()?;
            self.next += 4;
            self.left = 32;
        }

        self.left -= 1;
        Some((self.buffer >> self.left) & 1)
    }

    fn gamma(&mut self) -> Option<u32> {
        let mut value = 1u32;
        loop {
            value = value.checked_mul(2)?.checked_add(self.bit()?)?;
            if self.bit()? == 1 {
                return Some(value);
            }
        }
    }

    fn paired_gamma(&mut self) -> Option<u32> {
        let mut value = 1u32;
        loop {
            value = value.checked_mul(2)?.checked_add(self.bit()?)?;
            if self.bit()? == 1 {
                return Some(value);
            }
            value = (value - 1).checked_mul(2)?.checked_add(self.bit()?)?;
        }
    }
}

pub(super) fn decompress(source: &[u8], size: usize, variant: Variant) -> Option<Vec<u8>> {
    let mut bits = Bits {
        data: source,
        next: 0,
        buffer: 0,
        left: 0,
    };
    let mut output = Vec::with_capacity(size);
    let mut last_offset = 1u32;

    loop {
        while bits.bit()? == 1 {
            (output.len() < size).then_some(())?;
            output.push(bits.byte()?);
        }

        let high = match variant {
            Variant::B => bits.gamma()?,
            Variant::D | Variant::E => bits.paired_gamma()?,
        };

        let (offset, length_bit) = if high == REPEAT_OFFSET {
            let length_bit = match variant {
                Variant::B => None,
                Variant::D | Variant::E => Some(bits.bit()?),
            };
            (last_offset, length_bit)
        } else {
            let value = (high - OFFSET_BIAS)
                .checked_mul(256)?
                .checked_add(u32::from(bits.byte()?))?;
            if value == END_MARKER {
                return (output.len() == size).then_some(output);
            }

            last_offset = match variant {
                Variant::B => value + 1,
                Variant::D | Variant::E => (value >> 1) + 1,
            };
            let length_bit = match variant {
                Variant::B => None,
                Variant::D | Variant::E => Some(!value & 1),
            };
            (last_offset, length_bit)
        };

        let length = match variant {
            Variant::B | Variant::D => {
                let first = match length_bit {
                    Some(bit) => bit,
                    None => bits.bit()?,
                };
                match first * 2 + bits.bit()? {
                    0 => bits.gamma()? + 2,
                    length => length,
                }
            }
            Variant::E => match length_bit {
                Some(1) => 1 + bits.bit()?,
                _ if bits.bit()? == 1 => 3 + bits.bit()?,
                _ => bits.gamma()? + 3,
            },
        };
        let far = match variant {
            Variant::B => NRV2B_FAR,
            Variant::D | Variant::E => NRV2DE_FAR,
        };
        let length = (length + u32::from(offset > far) + 1) as usize;

        let from = output.len().checked_sub(offset as usize)?;
        (output.len().checked_add(length)? <= size).then_some(())?;
        for index in from..from + length {
            output.push(output[index]);
        }
    }
}
