use super::bitstream::{Bits, WordTags};
use super::{copy_match, output_buffer};
use crate::pe::image::read_u32;

const HEADER: usize = 4; // the unpacked size
const MIN_LENGTH: u32 = 2;
const OFFSET_BIAS: u32 = 2;

pub(crate) fn decompress(source: &[u8], size: usize) -> Option<Vec<u8>> {
    (read_u32(source, 0).ok()? as usize == size).then_some(())?;
    if size == 0 {
        return Some(Vec::new());
    }

    let mut bits = WordTags::new(source, HEADER);
    let mut output = output_buffer(size)?;
    output.push(bits.byte()?);

    while output.len() < size {
        if bits.bit()? == 0 {
            output.push(bits.byte()?);
            continue;
        }

        let length = bits.gamma()?.checked_add(MIN_LENGTH)?;
        let high = bits.gamma()?.checked_sub(OFFSET_BIAS)?;
        let offset = (high.checked_mul(256)? | u32::from(bits.byte()?)).checked_add(1)?;
        copy_match(&mut output, offset as usize, length as usize, size)?;
    }

    Some(output)
}
