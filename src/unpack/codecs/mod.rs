pub(crate) mod aplib;
pub(crate) mod bitstream;
pub(crate) mod brieflz;
pub(crate) mod call_filter;
pub(crate) mod ffce;
pub(crate) mod jcalg1;
pub(crate) mod lzma;
pub(crate) mod lzmat;
pub(crate) mod lzx;
pub(crate) mod nrv;

use crate::pe::MAX_IMAGE_SIZE;
use crate::pe::bytes::read_u32;

const MAX_RESERVED: usize = 1 << 24;

#[derive(Clone, Copy)]
pub(crate) enum DecodeError {
    Truncated,
    BadDistance,
    Overrun,
    BadHeader,
    TooLarge,
    Corrupt,
}

impl DecodeError {
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::Truncated => "its packed data ends early",
            Self::BadDistance => "a match in its packed data reaches before the start",
            Self::Overrun => "its packed data decodes past the size it declares",
            Self::BadHeader => "its packed data has an unknown header",
            Self::TooLarge => "its packed data declares an impossible size",
            Self::Corrupt => "its packed data is corrupt",
        }
    }
}

pub(crate) type Decoded<T = Vec<u8>> = Result<T, DecodeError>;

pub(crate) fn output_buffer(size: usize) -> Decoded {
    match size <= MAX_IMAGE_SIZE {
        true => Ok(Vec::with_capacity(size.min(MAX_RESERVED))),
        false => Err(DecodeError::TooLarge),
    }
}

pub(crate) fn declares_size(source: &[u8], at: usize, size: usize) -> Decoded<()> {
    let declared = read_u32(source, at).map_err(|_| DecodeError::Truncated)?;

    match declared as usize == size {
        true => Ok(()),
        false => Err(DecodeError::BadHeader),
    }
}

pub(crate) fn copy_match(
    output: &mut Vec<u8>,
    offset: usize,
    length: usize,
    size: usize,
) -> Decoded<()> {
    let from = output
        .len()
        .checked_sub(offset)
        .filter(|_| offset > 0)
        .ok_or(DecodeError::BadDistance)?;
    if output.len().saturating_add(length) > size {
        return Err(DecodeError::Overrun);
    }

    for index in from..from + length {
        output.push(output[index]);
    }
    Ok(())
}
