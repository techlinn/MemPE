use super::bitstream::{Bits, WordTags};
use super::{copy_match, output_buffer};
use crate::pe::image::read_u32;

const HEADER: usize = 4; // the unpacked size
const FLOOR_AFTER_LITERAL: u32 = 3; // fibonacci codes below the floor reuse the last offset
const FLOOR_AFTER_MATCH: u32 = 2;
const LOW_OFFSET_BITS: u32 = 6;
const FAR_OFFSET: u32 = 0x781; // matches this far back or further are one byte longer
const FARTHER_OFFSET: u32 = 0x8001;

pub(crate) fn decompress(source: &[u8], size: usize) -> Option<Vec<u8>> {
    (read_u32(source, 0).ok()? as usize == size).then_some(())?;
    if size == 0 {
        return Some(Vec::new());
    }

    let mut bits = WordTags::new(source, HEADER);
    let mut output = output_buffer(size)?;
    let mut last_offset = 0u32;
    let mut floor = FLOOR_AFTER_LITERAL;

    output.push(bits.byte()?);

    loop {
        if bits.bit()? == 0 {
            (output.len() < size).then_some(())?;
            output.push(bits.byte()?);
            floor = FLOOR_AFTER_LITERAL;
            continue;
        }

        if output.len() == size {
            return Some(output);
        }

        let code = fibonacci(&mut bits)?;
        let (offset, length) = match code.checked_sub(floor) {
            None => (last_offset, bits.gamma()?),
            Some(high) => {
                let offset = high
                    .checked_mul(1 << LOW_OFFSET_BITS)?
                    .checked_add(bits.number(LOW_OFFSET_BITS)?)?
                    .checked_add(1)?;
                let length = bits.gamma()?
                    + u32::from(offset >= FAR_OFFSET)
                    + u32::from(offset >= FARTHER_OFFSET);
                last_offset = offset;
                (offset, length)
            }
        };

        copy_match(&mut output, offset as usize, length as usize, size)?;
        floor = FLOOR_AFTER_MATCH;
    }
}

fn fibonacci(bits: &mut impl Bits) -> Option<u32> {
    let (mut previous, mut current, mut value) = (0u32, 1u32, 1u32);
    loop {
        (previous, current) = (current, previous.checked_add(current)?);
        if bits.bit()? == 0 {
            continue;
        }

        value = value.checked_add(current)?;
        (previous, current) = (current, previous.checked_add(current)?);
        if bits.bit()? == 1 {
            return Some(value); // two ones in a row end the code
        }
    }
}
