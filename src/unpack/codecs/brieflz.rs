use super::bitstream::{Bits, WordTags};
use super::{DecodeError, Decoded};
use super::{copy_match, declares_size, output_buffer};

const HEADER: usize = 4; // the unpacked size
const MIN_LENGTH: u32 = 2;
const OFFSET_BIAS: u32 = 2;

pub(crate) fn decompress(source: &[u8], size: usize) -> Decoded<Vec<u8>> {
    declares_size(source, 0, size)?;
    if size == 0 {
        return Ok(Vec::new());
    }

    let mut bits = WordTags::new(source, HEADER);
    let mut output = output_buffer(size)?;
    output.push(bits.byte()?);

    while output.len() < size {
        if bits.bit()? == 0 {
            output.push(bits.byte()?);
            continue;
        }

        let length = bits
            .gamma()?
            .checked_add(MIN_LENGTH)
            .ok_or(DecodeError::Corrupt)?;
        let high = bits
            .gamma()?
            .checked_sub(OFFSET_BIAS)
            .ok_or(DecodeError::Corrupt)?;
        let offset = (high.checked_mul(256).ok_or(DecodeError::Corrupt)? | u32::from(bits.byte()?))
            .checked_add(1)
            .ok_or(DecodeError::Corrupt)?;
        copy_match(&mut output, offset as usize, length as usize, size)?;
    }

    Ok(output)
}
