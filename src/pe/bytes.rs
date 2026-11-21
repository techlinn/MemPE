use crate::pe::PeKind;
use crate::{AppError, AppResult};

pub(crate) fn read_u16(bytes: &[u8], offset: usize) -> AppResult<u16> {
    let value = range(bytes, offset, 2, "PE field")?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

pub(crate) fn read_u32(bytes: &[u8], offset: usize) -> AppResult<u32> {
    let value = range(bytes, offset, 4, "PE field")?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

pub(crate) fn read_pointer(bytes: &[u8], offset: usize, kind: PeKind) -> AppResult<usize> {
    match kind {
        PeKind::Pe32 => Ok(read_u32(bytes, offset)? as usize),
        PeKind::Pe32Plus => {
            let value = range(bytes, offset, 8, "PE pointer")?;
            let pointer = u64::from_le_bytes([
                value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
            ]);
            usize::try_from(pointer).map_err(|_| AppError::new("PE pointer does not fit memory"))
        }
    }
}

pub(crate) fn relocation_block(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
    let page = read_u32(bytes, at).ok()?;
    let size = read_u32(bytes, at.checked_add(4)?).ok()?;

    Some((page as usize, size as usize)) // page rva, block size with header
}

pub(crate) fn relocation_words(body: &[u8]) -> impl Iterator<Item = u16> + '_ {
    let words = body.as_chunks::<2>().0;
    words.iter().map(|word| u16::from_le_bytes(*word))
}

pub(crate) fn read_ascii(bytes: &[u8], offset: usize, limit: usize) -> Option<&str> {
    let tail = bytes.get(offset..)?;
    let length = tail.iter().take(limit).position(|byte| *byte == 0)?;

    if length == 0 {
        return None;
    }

    std::str::from_utf8(tail.get(..length)?).ok()
}

pub(crate) fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> AppResult<()> {
    range_mut(bytes, offset, 2, "PE field")?.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub(crate) fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> AppResult<()> {
    range_mut(bytes, offset, 4, "PE field")?.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub(crate) fn write_u64(bytes: &mut [u8], offset: usize, value: u64) -> AppResult<()> {
    range_mut(bytes, offset, 8, "PE field")?.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub(crate) fn write_pointer(
    bytes: &mut [u8],
    offset: usize,
    kind: PeKind,
    value: u64,
) -> AppResult<()> {
    match kind {
        PeKind::Pe32 => {
            let value = u32::try_from(value)
                .map_err(|_| AppError::new("pointer does not fit a PE32 field"))?;
            write_u32(bytes, offset, value)
        }
        PeKind::Pe32Plus => write_u64(bytes, offset, value),
    }
}

pub(crate) fn require_range(bytes: &[u8], offset: usize, length: usize) -> AppResult<()> {
    range(bytes, offset, length, "PE structure").map(|_| ())
}

pub(crate) fn checked_add(left: usize, right: usize, field: &str) -> AppResult<usize> {
    left.checked_add(right)
        .ok_or_else(|| AppError::new(format!("{field} overflowed")))
}

// shannon entropy in bits per byte
pub(crate) fn entropy<'a>(bytes: impl IntoIterator<Item = &'a u8>) -> f64 {
    let mut counts = [0u64; 256];
    for byte in bytes {
        counts[usize::from(*byte)] += 1;
    }

    let total = counts.iter().sum::<u64>() as f64;
    -counts
        .iter()
        .filter(|count| **count != 0)
        .map(|count| {
            let share = *count as f64 / total;
            share * share.log2()
        })
        .sum::<f64>()
}

fn range<'a>(bytes: &'a [u8], offset: usize, length: usize, name: &str) -> AppResult<&'a [u8]> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| AppError::new(format!("{name} range overflowed")))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| AppError::new(format!("{name} lies outside the image")))
}

fn range_mut<'a>(
    bytes: &'a mut [u8],
    offset: usize,
    length: usize,
    name: &str,
) -> AppResult<&'a mut [u8]> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| AppError::new(format!("{name} range overflowed")))?;
    bytes
        .get_mut(offset..end)
        .ok_or_else(|| AppError::new(format!("{name} lies outside the image")))
}
