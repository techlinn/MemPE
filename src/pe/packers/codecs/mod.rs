pub(super) mod aplib;
pub(super) mod bitstream;
pub(super) mod brieflz;
pub(super) mod ffce;
pub(super) mod jcalg1;
pub(super) mod lzma;
pub(super) mod lzmat;
pub(super) mod lzx;
pub(super) mod nrv;

const MAX_RESERVED: usize = 1 << 24; // reserve this much at most, the rest grows as data arrives
const MAX_UNPACKED: usize = 1 << 30; // sizes come from packed files, no real image is this big

pub(crate) fn output_buffer(size: usize) -> Option<Vec<u8>> {
    (size <= MAX_UNPACKED).then(|| Vec::with_capacity(size.min(MAX_RESERVED)))
}

pub(crate) fn copy_match(
    output: &mut Vec<u8>,
    offset: usize,
    length: usize,
    size: usize,
) -> Option<()> {
    let from = output.len().checked_sub(offset)?;
    (offset > 0 && output.len().checked_add(length)? <= size).then_some(())?;
    for index in from..from + length {
        output.push(output[index]);
    }

    Some(())
}
