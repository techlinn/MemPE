use super::bitstream::{Bits, WordTags};
use super::{copy_match, output_buffer};
use crate::pe::image::read_u32;

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
const LENGTH_BONUSES: [(u32, u32); 4] = [(0x10000, 3), (0x37FF, 2), (0x27F, 1), (0x80, 0)]; // longer matches need fewer extra bytes
const NEAR_BONUS: u32 = 4;

pub(crate) fn decompress(source: &[u8], size: usize) -> Option<Vec<u8>> {
    (source.get(..MAGIC.len())? == MAGIC).then_some(())?;
    (read_u32(source, SIZE_OFFSET).ok()? as usize == size).then_some(())?;

    let mut bits = WordTags::new(source, HEADER);
    let mut output = output_buffer(size)?;
    let mut last_offset = 1u32;
    let mut index_bits = DEFAULT_BITS;
    let mut literal_bits = DEFAULT_BITS;
    let mut literal_base = 0u8;

    loop {
        if bits.bit()? == 1 {
            (output.len() < size).then_some(())?;
            let value = u8::try_from(bits.number(literal_bits)?).ok()?;
            output.push(value.wrapping_add(literal_base));
            continue;
        }

        let (offset, length) = if bits.bit()? == 1 {
            let high = bits.gamma()?;
            if high == REPEAT_OFFSET {
                (last_offset, bits.gamma()?)
            } else {
                let offset = high
                    .checked_sub(REPEAT_OFFSET + 1)?
                    .checked_shl(index_bits)?
                    | bits.number(index_bits)?;
                let bonus = LENGTH_BONUSES
                    .iter()
                    .find(|(threshold, _)| offset >= *threshold)
                    .map_or(NEAR_BONUS, |(_, bonus)| *bonus);
                last_offset = offset;
                (offset, bits.gamma()?.checked_add(bonus)?)
            }
        } else if bits.bit()? == 0 {
            let offset = bits.number(SHORT_OFFSET_BITS)?;
            let length = bits.number(SHORT_LENGTH_BITS)? + SHORT_MIN_LENGTH;

            match (offset, length) {
                (0, SHORT_MIN_LENGTH) => return (output.len() == size).then_some(output),
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
                    (output.len() < size).then_some(())?;
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
                        _ => byte(&mut bits)?,
                    };
                    continue;
                }
                near => (near - 1, 1),
            }
        };

        copy_match(&mut output, offset as usize, length as usize, size)?;
    }
}

fn copy_raw_runs(bits: &mut WordTags<'_>, output: &mut Vec<u8>, size: usize) -> Option<()> {
    loop {
        (output.len().checked_add(RAW_RUN)? <= size).then_some(())?;
        for _ in 0..RAW_RUN {
            output.push(byte(bits)?);
        }

        if bits.bit()? == 0 {
            return Some(());
        }
    }
}

fn byte(bits: &mut WordTags<'_>) -> Option<u8> {
    u8::try_from(bits.number(DEFAULT_BITS)?).ok()
}
