use super::bitstream::{Bits, WordTags};
use super::{DecodeError, Decoded};
use super::{copy_match, declares_size, output_buffer};

pub(crate) const MAGIC: &[u8; 2] = b"JC";
const SIZE_OFFSET: usize = 2;
const HEADER: usize = 10; // magic, unpacked size and checksum
const DEFAULT_BITS: u32 = 8;
const REPEAT_OFFSET: u32 = 2;
const SHORT_OFFSET_BITS: u32 = 7;
const SHORT_LENGTH_BITS: u32 = 2;
const SHORT_MIN_LENGTH: u32 = 2;
const NEAR_OFFSET_BITS: u32 = 4;
const ZERO_BYTE: u32 = 1; // a near offset of one writes a zero
const RAW_RUN: usize = 256;
const SMALL_LITERAL_BITS: u32 = 7;
const LENGTH_BONUSES: [(u32, u32); 4] = [(0x10000, 3), (0x37FF, 2), (0x27F, 1), (0x80, 0)];
const NEAR_BONUS: u32 = 4;

pub(crate) fn decompress(source: &[u8], size: usize) -> Decoded<Vec<u8>> {
    if source.get(..MAGIC.len()).ok_or(DecodeError::Truncated)? != MAGIC {
        return Err(DecodeError::BadHeader);
    }
    declares_size(source, SIZE_OFFSET, size)?;

    let mut bits = WordTags::new(source, HEADER);
    let mut output = output_buffer(size)?;
    let mut last_offset = 1u32;
    let mut index_bits = DEFAULT_BITS;
    let mut literal_bits = DEFAULT_BITS;
    let mut literal_base = 0u8;

    loop {
        if bits.bit()? == 1 {
            if output.len() >= size {
                return Err(DecodeError::Overrun);
            }
            let value =
                u8::try_from(bits.number(literal_bits)?).map_err(|_| DecodeError::Corrupt)?;
            output.push(value.wrapping_add(literal_base));
            continue;
        }

        let (offset, length) = if bits.bit()? == 1 {
            let high = bits.gamma()?;
            if high == REPEAT_OFFSET {
                (last_offset, bits.gamma()?)
            } else {
                let scale = 1u32.checked_shl(index_bits).ok_or(DecodeError::Corrupt)?;
                let offset = high
                    .checked_sub(REPEAT_OFFSET + 1)
                    .ok_or(DecodeError::Corrupt)?
                    .checked_mul(scale)
                    .ok_or(DecodeError::Corrupt)?
                    | bits.number(index_bits)?;
                let bonus = LENGTH_BONUSES
                    .iter()
                    .find(|(threshold, _)| offset >= *threshold)
                    .map_or(NEAR_BONUS, |(_, bonus)| *bonus);
                last_offset = offset;
                (
                    offset,
                    bits.gamma()?
                        .checked_add(bonus)
                        .ok_or(DecodeError::Corrupt)?,
                )
            }
        } else if bits.bit()? == 0 {
            let offset = bits.number(SHORT_OFFSET_BITS)?;
            let length = bits.number(SHORT_LENGTH_BITS)? + SHORT_MIN_LENGTH;

            match (offset, length) {
                (0, SHORT_MIN_LENGTH) if output.len() == size => return Ok(output),
                (0, SHORT_MIN_LENGTH) => return Err(DecodeError::Truncated),
                (0, _) => {
                    index_bits = bits.number(length + 1)?;
                    continue;
                }
                _ => {
                    last_offset = offset;
                    (offset, length)
                }
            }
        } else {
            match bits.number(NEAR_OFFSET_BITS)? {
                ZERO_BYTE => {
                    if output.len() >= size {
                        return Err(DecodeError::Overrun);
                    }
                    output.push(0);
                    continue;
                }
                0 if bits.bit()? == 1 => {
                    copy_raw_runs(&mut bits, &mut output, size)?;
                    continue;
                }
                0 => {
                    literal_bits = bits.number(1)? + SMALL_LITERAL_BITS;
                    literal_base = match literal_bits {
                        DEFAULT_BITS => 0,
                        _ => eight_bits(&mut bits)?,
                    };
                    continue;
                }
                near => (near - 1, 1),
            }
        };

        copy_match(&mut output, offset as usize, length as usize, size)?;
    }
}

fn copy_raw_runs(bits: &mut WordTags<'_>, output: &mut Vec<u8>, size: usize) -> Decoded<()> {
    loop {
        if output.len().saturating_add(RAW_RUN) > size {
            return Err(DecodeError::Overrun);
        }

        for _ in 0..RAW_RUN {
            output.push(eight_bits(bits)?);
        }

        if bits.bit()? == 0 {
            return Ok(());
        }
    }
}

fn eight_bits(bits: &mut WordTags<'_>) -> Decoded<u8> {
    // from the bit stream, unlike bits.byte()
    u8::try_from(bits.number(DEFAULT_BITS)?).map_err(|_| DecodeError::Corrupt)
}
