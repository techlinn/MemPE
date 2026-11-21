use super::bitstream::{Bits, WordTags};
use super::{DecodeError, Decoded};
use super::{copy_match, output_buffer};

const END_MARKER: u32 = u32::MAX;
const REPEAT_OFFSET: u32 = 2;
const OFFSET_BIAS: u32 = 3;
const NRV2B_FAR: u32 = 0xD00; // further back: one byte longer
const NRV2DE_FAR: u32 = 0x500;
const GAMMA_STOP: u32 = 1;

#[derive(Clone, Copy)]
pub(crate) enum Variant {
    B,
    D,
    E,
}

fn paired_gamma(bits: &mut WordTags<'_>) -> Decoded<u32> {
    let mut value = 1u32;
    loop {
        value = value
            .checked_mul(2)
            .ok_or(DecodeError::Corrupt)?
            .checked_add(bits.bit()?)
            .ok_or(DecodeError::Corrupt)?;
        if bits.bit()? == GAMMA_STOP {
            return Ok(value);
        }
        value = (value - 1)
            .checked_mul(2)
            .ok_or(DecodeError::Corrupt)?
            .checked_add(bits.bit()?)
            .ok_or(DecodeError::Corrupt)?;
    }
}

pub(crate) fn decompress(source: &[u8], size: usize, variant: Variant) -> Decoded<Vec<u8>> {
    let mut bits = WordTags::new(source, 0);
    let mut output = output_buffer(size)?;
    let mut last_offset = 1u32;

    loop {
        while bits.bit()? == 1 {
            if output.len() >= size {
                return Err(DecodeError::Overrun);
            }
            output.push(bits.byte()?);
        }

        let high = match variant {
            Variant::B => bits.gamma_ending(GAMMA_STOP)?,
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
                .checked_mul(256)
                .ok_or(DecodeError::Corrupt)?
                .checked_add(u32::from(bits.byte()?))
                .ok_or(DecodeError::Corrupt)?;
            if value == END_MARKER {
                return match output.len() == size {
                    true => Ok(output),
                    false => Err(DecodeError::Truncated),
                };
            }

            let (offset, length_bit) = match variant {
                Variant::B => (value + 1, None),
                Variant::D | Variant::E => ((value >> 1) + 1, Some(!value & 1)),
            };
            last_offset = offset;
            (offset, length_bit)
        };

        let length = match variant {
            Variant::B | Variant::D => {
                let first = match length_bit {
                    Some(bit) => bit,
                    None => bits.bit()?,
                };
                match first * 2 + bits.bit()? {
                    0 => bits.gamma_ending(GAMMA_STOP)?.saturating_add(2),
                    length => length,
                }
            }
            Variant::E => match length_bit {
                Some(1) => 1 + bits.bit()?,
                _ if bits.bit()? == 1 => 3 + bits.bit()?,
                _ => bits.gamma_ending(GAMMA_STOP)?.saturating_add(3),
            },
        };
        let far = match variant {
            Variant::B => NRV2B_FAR,
            Variant::D | Variant::E => NRV2DE_FAR,
        };
        let length = length as usize + usize::from(offset > far) + 1;
        copy_match(&mut output, offset as usize, length, size)?;
    }
}
