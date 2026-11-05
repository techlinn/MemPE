use super::bitstream::{Bits, WordTags};
use super::{copy_match, output_buffer};

const END_MARKER: u32 = u32::MAX;
const REPEAT_OFFSET: u32 = 2;
const OFFSET_BIAS: u32 = 3;
const NRV2B_FAR: u32 = 0xD00; // matches further back than this are one byte longer
const NRV2DE_FAR: u32 = 0x500;

#[derive(Clone, Copy)]
pub(crate) enum Variant {
    B,
    D,
    E,
}

fn gamma(bits: &mut WordTags<'_>) -> Option<u32> {
    let mut value = 1u32;
    loop {
        value = value.checked_mul(2)?.checked_add(bits.bit()?)?;
        if bits.bit()? == 1 {
            return Some(value);
        }
    }
}

fn paired_gamma(bits: &mut WordTags<'_>) -> Option<u32> {
    let mut value = 1u32;
    loop {
        value = value.checked_mul(2)?.checked_add(bits.bit()?)?;
        if bits.bit()? == 1 {
            return Some(value);
        }
        value = (value - 1).checked_mul(2)?.checked_add(bits.bit()?)?;
    }
}

pub(crate) fn decompress(source: &[u8], size: usize, variant: Variant) -> Option<Vec<u8>> {
    let mut bits = WordTags::new(source, 0);
    let mut output = output_buffer(size)?;
    let mut last_offset = 1u32;

    loop {
        while bits.bit()? == 1 {
            (output.len() < size).then_some(())?;
            output.push(bits.byte()?);
        }

        let high = match variant {
            Variant::B => gamma(&mut bits)?,
            Variant::D | Variant::E => paired_gamma(&mut bits)?,
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
                    0 => gamma(&mut bits)? + 2,
                    length => length,
                }
            }
            Variant::E => match length_bit {
                Some(1) => 1 + bits.bit()?,
                _ if bits.bit()? == 1 => 3 + bits.bit()?,
                _ => gamma(&mut bits)? + 3,
            },
        };
        let far = match variant {
            Variant::B => NRV2B_FAR,
            Variant::D | Variant::E => NRV2DE_FAR,
        };
        let length = (length + u32::from(offset > far) + 1) as usize;
        copy_match(&mut output, offset as usize, length, size)?;
    }
}
