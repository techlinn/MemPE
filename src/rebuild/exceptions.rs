use super::{SectionLayout, rva_to_file};
use crate::pe::bytes::read_u32;
use crate::pe::{CLR_DIRECTORY, EXCEPTION_DIRECTORY, FUNCTION_END_OFFSET, PeKind, PeModel, Rva};
use crate::pe::{RUNTIME_FUNCTION_SIZE, UNWIND_CHAINED, UNWIND_INFO_OFFSET, UNWIND_VERSION_MASK};
use crate::{AppError, AppResult};

const UNWIND_VERSIONS: [u8; 2] = [1, 2];

pub(super) fn is_managed(output: &[u8], model: &PeModel) -> bool {
    model.directory(output, CLR_DIRECTORY).is_some()
}

pub(super) fn repair_exception_directory(
    output: &mut [u8],
    model: &PeModel,
    layouts: &[SectionLayout<'_>],
    header_size: usize,
) -> AppResult<ExceptionRepair> {
    if model.kind != PeKind::Pe32Plus {
        return Ok(ExceptionRepair::absent());
    }

    let Some(directory) = model.directory(output, EXCEPTION_DIRECTORY) else {
        return Ok(ExceptionRepair::absent());
    };

    let (rva, size) = (directory.rva().get(), directory.size() as usize);
    let Some(file_offset) = rva_to_file(rva, layouts, header_size) else {
        return Ok(ExceptionRepair::absent());
    };

    let scan =
        collect_valid_runtime_functions(output, model, layouts, header_size, file_offset, size);
    let ranges = runtime_function_ranges(&scan.valid);

    if scan.invalid == 0 {
        return Ok(ExceptionRepair {
            invalid: 0,
            ranges: Some(ranges),
            cleared: false,
        });
    }

    write_valid_runtime_functions(output, model, rva, file_offset, size, &scan.valid)?;

    Ok(ExceptionRepair {
        invalid: scan.invalid,
        ranges: Some(ranges),
        cleared: scan.valid.is_empty(),
    })
}

pub(super) type UnwindRanges = Vec<(u32, u32)>;

pub(super) struct ExceptionRepair {
    pub(super) invalid: usize,
    pub(super) ranges: Option<UnwindRanges>,
    pub(super) cleared: bool,
}

impl ExceptionRepair {
    fn absent() -> Self {
        Self {
            invalid: 0,
            ranges: None,
            cleared: false,
        }
    }
}

struct ExceptionScan {
    valid: Vec<[u8; RUNTIME_FUNCTION_SIZE]>,
    invalid: usize,
}

fn collect_valid_runtime_functions(
    output: &[u8],
    model: &PeModel,
    layouts: &[SectionLayout<'_>],
    header_size: usize,
    file_offset: usize,
    size: usize,
) -> ExceptionScan {
    let managed = is_managed(output, model);
    let declared = size / RUNTIME_FUNCTION_SIZE;
    let table = output.get(file_offset..).unwrap_or_default();

    let valid = table
        .as_chunks::<RUNTIME_FUNCTION_SIZE>()
        .0
        .iter()
        .take(declared)
        .filter(|entry| {
            runtime_function_is_valid(
                output,
                entry.as_slice(),
                model,
                layouts,
                header_size,
                managed,
            )
        })
        .copied()
        .collect::<Vec<_>>();
    let invalid = usize::from(!size.is_multiple_of(RUNTIME_FUNCTION_SIZE))
        .saturating_add(declared.saturating_sub(valid.len()));

    ExceptionScan { valid, invalid }
}

fn runtime_function_ranges(valid: &[[u8; RUNTIME_FUNCTION_SIZE]]) -> UnwindRanges {
    valid
        .iter()
        .filter_map(|entry| {
            Some((
                read_u32(entry, 0).ok()?,
                read_u32(entry, FUNCTION_END_OFFSET).ok()?,
            ))
        })
        .collect()
}

fn write_valid_runtime_functions(
    output: &mut [u8],
    model: &PeModel,
    rva: u32,
    file_offset: usize,
    size: usize,
    valid: &[[u8; RUNTIME_FUNCTION_SIZE]],
) -> AppResult<()> {
    let range_end = file_offset
        .checked_add(size)
        .ok_or_else(|| AppError::new("exception-directory range overflowed"))?;
    let destination = output
        .get_mut(file_offset..range_end)
        .ok_or_else(|| AppError::new("exception directory lies outside the rebuilt PE"))?;
    destination.fill(0);

    let (slots, _) = destination.as_chunks_mut::<RUNTIME_FUNCTION_SIZE>();
    for (slot, entry) in slots.iter_mut().zip(valid) {
        *slot = *entry;
    }

    if valid.is_empty() {
        model.clear_directory(output, EXCEPTION_DIRECTORY);
        return Ok(());
    }

    let new_size = valid.len().saturating_mul(RUNTIME_FUNCTION_SIZE);
    model
        .set_directory(output, EXCEPTION_DIRECTORY, rva as usize, new_size)
        .ok_or_else(|| AppError::new("exception-directory size overflowed"))
}

pub(super) fn entry_unwind_covered(ranges: &Option<UnwindRanges>, entry: u32) -> Option<bool> {
    let ranges = ranges.as_ref()?;
    Some(
        ranges
            .iter()
            .any(|(begin, end)| entry >= *begin && entry < *end),
    )
}

pub(super) fn runtime_function_is_valid(
    output: &[u8],
    entry: &[u8],
    model: &PeModel,
    layouts: &[SectionLayout<'_>],
    header_size: usize,
    managed: bool,
) -> bool {
    let (Ok(begin), Ok(end), Ok(unwind)) = (
        read_u32(entry, 0),
        read_u32(entry, FUNCTION_END_OFFSET),
        read_u32(entry, UNWIND_INFO_OFFSET),
    ) else {
        return false;
    };

    if begin >= end
        || !model.executable_rva(Rva(begin))
        || !model.executable_rva(Rva(end.saturating_sub(1)))
    {
        return false;
    }

    let Some(unwind_offset) = rva_to_file(unwind & !UNWIND_CHAINED, layouts, header_size) else {
        return false;
    };

    if unwind & UNWIND_CHAINED != 0 {
        let target = output.get(unwind_offset..unwind_offset.saturating_add(RUNTIME_FUNCTION_SIZE));
        return target.is_some_and(|other| {
            read_u32(other, 0).ok() < read_u32(other, FUNCTION_END_OFFSET).ok()
        });
    }

    let Some(first) = output.get(unwind_offset).copied() else {
        return false;
    };

    managed || UNWIND_VERSIONS.contains(&(first & UNWIND_VERSION_MASK))
}
