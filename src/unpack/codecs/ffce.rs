use super::bitstream::{Bits, WordTags};
use super::{DecodeError, Decoded};
use super::{copy_match, declares_size, output_buffer};

const HEADER: usize = 4; // the unpacked size
const FLOOR_AFTER_LITERAL: u32 = 3; // codes below the floor reuse the last offset
const FLOOR_AFTER_MATCH: u32 = 2;
const LOW_OFFSET_BITS: u32 = 6;
const FAR_OFFSET: u32 = 0x781; // this far back: one byte longer
const FARTHER_OFFSET: u32 = 0x8001;

pub(crate) fn decompress(source: &[u8], size: usize) -> Decoded<Vec<u8>> {
    declares_size(source, 0, size)?;
    if size == 0 {
        return Ok(Vec::new());
    }

    let mut bits = WordTags::new(source, HEADER);
    let mut output = output_buffer(size)?;
    let mut last_offset = 0u32;
    let mut floor = FLOOR_AFTER_LITERAL;

    output.push(bits.byte()?);

    loop {
        if bits.bit()? == 0 {
            if output.len() >= size {
                return Err(DecodeError::Overrun);
            }
            output.push(bits.byte()?);
            floor = FLOOR_AFTER_LITERAL;
            continue;
        }

        if output.len() == size {
            return Ok(output);
        }

        let code = fibonacci(&mut bits)?;
        let (offset, length) = match code.checked_sub(floor) {
            None => (last_offset, bits.gamma()?),
            Some(high) => {
                let offset = high
                    .checked_mul(1 << LOW_OFFSET_BITS)
                    .ok_or(DecodeError::Corrupt)?
                    .checked_add(bits.number(LOW_OFFSET_BITS)?)
                    .ok_or(DecodeError::Corrupt)?
                    .checked_add(1)
                    .ok_or(DecodeError::Corrupt)?;
                let length = bits
                    .gamma()?
                    .saturating_add(u32::from(offset >= FAR_OFFSET))
                    .saturating_add(u32::from(offset >= FARTHER_OFFSET));
                last_offset = offset;
                (offset, length)
            }
        };

        copy_match(&mut output, offset as usize, length as usize, size)?;
        floor = FLOOR_AFTER_MATCH;
    }
}

fn fibonacci(bits: &mut impl Bits) -> Decoded<u32> {
    let (mut previous, mut current, mut value) = (0u32, 1u32, 1u32);
    loop {
        (previous, current) = (
            current,
            previous.checked_add(current).ok_or(DecodeError::Corrupt)?,
        );
        if bits.bit()? == 0 {
            continue;
        }

        value = value.checked_add(current).ok_or(DecodeError::Corrupt)?;
        (previous, current) = (
            current,
            previous.checked_add(current).ok_or(DecodeError::Corrupt)?,
        );
        if bits.bit()? == 1 {
            return Ok(value); // two ones in a row end the code
        }
    }
}
