use super::bitstream::Bits;
use super::{DecodeError, Decoded};
use super::{copy_match, output_buffer};

const REPEAT_OFFSET: u32 = 2; // gamma offset 2 repeats the last offset
const OFFSET_BIAS: u32 = 3;
const OFFSET_HIGH_SCALE: u32 = 0x100; // a byte holds the low part
const LONG_OFFSET: u32 = 0x7D00;
const MEDIUM_OFFSET: u32 = 0x500;
const SHORT_OFFSET: u32 = 0x80;
const NEAR_BITS: u32 = 4;

#[derive(Clone, Copy)]
pub(crate) enum Variant {
    Original, // < 0.30: every offset 2 repeats
    Classic,  // aplib >= 0.30 offset rule
}

pub(crate) fn decompress_exact(bits: impl Bits, size: usize, variant: Variant) -> Decoded<Vec<u8>> {
    let output = decompress(bits, size, variant)?;

    match output.len() == size {
        true => Ok(output),
        false => Err(DecodeError::Truncated),
    }
}

// size is a limit: the end marker may come sooner
pub(crate) fn decompress(mut bits: impl Bits, size: usize, variant: Variant) -> Decoded<Vec<u8>> {
    let mut output = output_buffer(size)?;
    let mut last_offset = 0u32;
    let mut after_literal = true;

    output.push(bits.byte()?);

    loop {
        if output.len() > size {
            // only the end marker may follow a full buffer
            return Err(DecodeError::Overrun);
        }

        if bits.bit()? == 0 {
            output.push(bits.byte()?);
            after_literal = true;
            continue;
        }

        let (offset, length) = if bits.bit()? == 0 {
            let high = bits.gamma()?;
            let repeats =
                high == REPEAT_OFFSET && (after_literal || matches!(variant, Variant::Original));

            if repeats {
                (last_offset, bits.gamma()?)
            } else {
                let bias = match variant {
                    Variant::Classic if !after_literal => OFFSET_BIAS - 1,
                    _ => OFFSET_BIAS,
                };
                let offset = high
                    .checked_sub(bias)
                    .ok_or(DecodeError::Corrupt)?
                    .checked_mul(OFFSET_HIGH_SCALE)
                    .ok_or(DecodeError::Corrupt)?
                    | u32::from(bits.byte()?);
                let length = bits.gamma()?.saturating_add(match offset {
                    LONG_OFFSET.. => 2,
                    MEDIUM_OFFSET.. => 1,
                    0..SHORT_OFFSET => 2,
                    _ => 0,
                });
                last_offset = offset;
                (offset, length)
            }
        } else if bits.bit()? == 0 {
            let byte = u32::from(bits.byte()?);
            let offset = byte >> 1;

            if offset == 0 {
                return Ok(output);
            }

            last_offset = offset;
            (offset, 2 + (byte & 1))
        } else {
            let offset = bits.number(NEAR_BITS)?;
            let byte = match offset {
                0 => 0,
                _ => *output
                    .get(
                        output
                            .len()
                            .checked_sub(offset as usize)
                            .ok_or(DecodeError::BadDistance)?,
                    )
                    .ok_or(DecodeError::BadDistance)?,
            };

            output.push(byte);
            after_literal = true;
            continue;
        };

        copy_match(&mut output, offset as usize, length as usize, size)?;
        after_literal = false;
    }
}
