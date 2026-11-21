use std::ops::Range;

use super::lost_directories::FOUND_BY_SEARCH;
use super::{Restoration, SCAN_STEP, rewrite_table, unique};
use crate::pe::bytes::read_u32;
use crate::pe::{
    EXCEPTION_DIRECTORY, PeKind, PeModel, RUNTIME_FUNCTION_SIZE, UNWIND_INFO_OFFSET,
    first_section_rva,
};

pub(crate) fn restore_exception_directory(
    restored: &mut [u8],
    model: &PeModel,
    end: usize,
) -> Restoration {
    let Some(copy) = model.directory(restored, EXCEPTION_DIRECTORY) else {
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
    let Some(image_start) = first_section_rva(&model.sections) else {
        return Restoration::Lost;
    };

    let original = unique(
        (image_start..end)
            .step_by(SCAN_STEP)
            .filter(|at| entry(restored, *at, 0).as_ref() == Some(&first)),
    ); // program entries first, packer's last
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

    match model.set_directory(
        restored,
        EXCEPTION_DIRECTORY,
        original,
        kept * RUNTIME_FUNCTION_SIZE,
    ) {
        Some(()) => Restoration::Inferred(FOUND_BY_SEARCH),
        None => Restoration::Failed,
    }
}

pub(super) struct RuntimeFunction {
    pub(super) begin: usize,
    pub(super) unwind_info: usize,
}

pub(super) fn runtime_functions(bytes: &[u8], model: &PeModel) -> Vec<RuntimeFunction> {
    if model.kind != PeKind::Pe32Plus {
        return Vec::new(); // the 12 byte entry is the x64 one
    }
    let Some(directory) = model.directory(bytes, EXCEPTION_DIRECTORY) else {
        return Vec::new();
    };

    let start = directory.rva().as_usize();
    let table = bytes
        .get(start..start.saturating_add(directory.size() as usize))
        .unwrap_or_default();
    table
        .as_chunks::<RUNTIME_FUNCTION_SIZE>()
        .0
        .iter()
        .filter_map(|function| {
            Some(RuntimeFunction {
                begin: read_u32(function.as_slice(), 0).ok()? as usize,
                unwind_info: read_u32(function.as_slice(), UNWIND_INFO_OFFSET).ok()? as usize,
            })
        })
        .collect()
}

pub(crate) fn keep_unwind_within(
    restored: &mut [u8],
    model: &PeModel,
    code: &[Range<usize>],
) -> Option<usize> {
    let mut dropped = 0;
    rewrite_table(restored, model, EXCEPTION_DIRECTORY, |table| {
        let kept: Vec<u8> = table
            .as_chunks::<RUNTIME_FUNCTION_SIZE>()
            .0
            .iter()
            .filter(|function| {
                let begin = read_u32(function.as_slice(), 0).map_or(0, |begin| begin as usize);
                code.iter().any(|range| range.contains(&begin)) // vm handlers listed by packers
            })
            .flatten()
            .copied()
            .collect();
        dropped = (table.len() - kept.len()) / RUNTIME_FUNCTION_SIZE;
        kept
    })?;

    Some(dropped)
}
