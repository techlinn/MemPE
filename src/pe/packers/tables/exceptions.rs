use std::ops::Range;

use super::{FIRST_SECTION_RVA, Restoration, SCAN_STEP, set_directory, unique};
use crate::pe::image::{read_u32, write_u32};
use crate::pe::{EXCEPTION_DIRECTORY, PeModel, RUNTIME_FUNCTION_SIZE};

pub(crate) fn restore_exception_directory(
    restored: &mut [u8],
    model: &PeModel,
    end: usize,
) -> Restoration {
    let Ok(Some(copy)) = model.directory(restored, EXCEPTION_DIRECTORY) else {
        return Restoration::Absent;
    };

    let copy_start = copy.rva().as_usize();
    if copy_start < end {
        return Restoration::Absent;
    }

    let entry = |bytes: &[u8], table: usize, index: usize| {
        let at = table.checked_add(index.checked_mul(RUNTIME_FUNCTION_SIZE)?)?;
        bytes
            .get(at..at.checked_add(RUNTIME_FUNCTION_SIZE)?)
            .map(<[u8]>::to_vec)
    };
    let Some(first) = entry(restored, copy_start, 0) else {
        return Restoration::Absent;
    };

    let original = unique(
        (FIRST_SECTION_RVA..end)
            .step_by(SCAN_STEP)
            .filter(|at| entry(restored, *at, 0).as_ref() == Some(&first)),
    ); // the packer's copy starts with the program's entries and ends with its own
    let Some(original) = original else {
        return Restoration::Lost;
    };

    let count = copy.size() as usize / RUNTIME_FUNCTION_SIZE;
    let kept = (0..count)
        .take_while(|index| {
            original + (index + 1) * RUNTIME_FUNCTION_SIZE <= end
                && entry(restored, original, *index) == entry(restored, copy_start, *index)
        })
        .count();

    match set_directory(
        restored,
        model,
        EXCEPTION_DIRECTORY,
        original,
        kept * RUNTIME_FUNCTION_SIZE,
    ) {
        Some(()) => Restoration::Restored,
        None => Restoration::Failed,
    }
}

pub(crate) fn keep_unwind_within(
    restored: &mut [u8],
    model: &PeModel,
    code: &[Range<usize>],
) -> Option<usize> {
    let entry = model.directory_offset(EXCEPTION_DIRECTORY).ok()??;
    let rva = read_u32(restored, entry).ok()? as usize;
    let size = read_u32(restored, entry + 4).ok()? as usize;
    let table = restored.get(rva..rva.checked_add(size)?)?.to_vec();

    let kept: Vec<u8> = table
        .as_chunks::<RUNTIME_FUNCTION_SIZE>()
        .0
        .iter()
        .filter(|function| {
            let begin = read_u32(function.as_slice(), 0).map_or(0, |begin| begin as usize);
            code.iter().any(|range| range.contains(&begin)) // packers list their vm handlers here and disassemblers carve functions from the junk
        })
        .flatten()
        .copied()
        .collect();

    let area = restored.get_mut(rva..rva + size)?;
    area.fill(0);
    area[..kept.len()].copy_from_slice(&kept);
    write_u32(restored, entry + 4, u32::try_from(kept.len()).ok()?).ok()?;
    Some((table.len() - kept.len()) / RUNTIME_FUNCTION_SIZE)
}
