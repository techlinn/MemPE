use super::bitstream::Bits;
use super::{copy_match, output_buffer};

const REPEAT_OFFSET: u32 = 2; // a gamma offset of 2 reuses the previous match offset
const OFFSET_BIAS: u32 = 3;
const LONG_OFFSET: u32 = 0x7D00;
const MEDIUM_OFFSET: u32 = 0x500;
const SHORT_OFFSET: u32 = 0x80;
const NEAR_BITS: u32 = 4;

#[derive(Clone, Copy)]
pub(crate) enum Variant {
    Original, // before aplib 0.30 every gamma offset of 2 repeats the last offset
    Classic,  // later only right after a literal, and a match lowers the next offset bias by one
}

pub(crate) fn decompress(mut bits: impl Bits, size: usize, variant: Variant) -> Option<Vec<u8>> {
    let mut output = output_buffer(size)?;
    let mut last_offset = 0u32;
    let mut after_literal = true;

    output.push(bits.byte()?);

    loop {
        (output.len() <= size).then_some(())?; // a full buffer may only be followed by the end marker

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
                let offset = (high.checked_sub(bias)? << 8) | u32::from(bits.byte()?);
                let length = bits.gamma()?
                    + match offset {
                        LONG_OFFSET.. => 2,
                        MEDIUM_OFFSET.. => 1,
                        0..SHORT_OFFSET => 2,
                        _ => 0,
                    };
                last_offset = offset;
                (offset, length)
            }
        } else if bits.bit()? == 0 {
            let byte = u32::from(bits.byte()?);
            let offset = byte >> 1;

            if offset == 0 {
                return Some(output);
            }

            last_offset = offset;
            (offset, 2 + (byte & 1))
        } else {
            let offset = bits.number(NEAR_BITS)?;
            let byte = match offset {
                0 => 0,
                _ => *output.get(output.len().checked_sub(offset as usize)?)?,
            };

            output.push(byte);
            after_literal = true;
            continue;
        };

        copy_match(&mut output, offset as usize, length as usize, size)?;
        after_literal = false;
    }
}
