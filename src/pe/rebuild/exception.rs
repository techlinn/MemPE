use super::{SectionLayout, rva_to_file};
use crate::pe::image::{read_u32, write_u32};
use crate::pe::{PeKind, PeModel, Rva};
use crate::{AppError, AppResult};

pub(super) const EXCEPTION_DIRECTORY: usize = 3;
pub(super) const RUNTIME_FUNCTION_SIZE: usize = 12;
const COM_DESCRIPTOR_DIRECTORY: usize = 14;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum UnwindLayout {
    Native,
    Managed,
}

impl UnwindLayout {
    pub(super) fn is_managed(self) -> bool {
        self == Self::Managed
    }
}

pub(super) fn unwind_layout(output: &[u8], model: &PeModel) -> UnwindLayout {
    let Ok(Some(offset)) = model.directory_offset(COM_DESCRIPTOR_DIRECTORY) else {
        return UnwindLayout::Native;
    };
    match read_u32(output, offset) {
        Ok(rva) if rva != 0 => UnwindLayout::Managed,
        _ => UnwindLayout::Native,
    }
}

pub(super) fn repair_exception_directory(
    output: &mut [u8],
    model: &PeModel,
    layouts: &[SectionLayout<'_>],
    header_size: usize,
) -> AppResult<ExceptionRepair> {
    if model.kind != PeKind::Pe32Plus || EXCEPTION_DIRECTORY >= model.directory_count {
        return Ok(ExceptionRepair::absent());
    }
    let entry_offset = model
        .directory_offset(EXCEPTION_DIRECTORY)?
        .ok_or_else(|| AppError::new("exception-directory slot is missing"))?;
    let rva = read_u32(output, entry_offset)?;
    let size = read_u32(output, entry_offset.saturating_add(4))? as usize;
    if rva == 0 || size == 0 {
        return Ok(ExceptionRepair::absent());
    }
    let Some(file_offset) = rva_to_file(rva, layouts, header_size) else {
        return Ok(ExceptionRepair::absent());
    };
    let scan =
        collect_valid_runtime_functions(output, model, layouts, header_size, file_offset, size)?;
    let ranges = runtime_function_ranges(&scan.valid);
    if scan.invalid == 0 {
        return Ok(ExceptionRepair {
            invalid: 0,
            ranges: Some(ranges),
        });
    }
    write_valid_runtime_functions(output, entry_offset, file_offset, size, &scan.valid)?;
    Ok(ExceptionRepair {
        invalid: scan.invalid,
        ranges: Some(ranges),
    })
}

pub(super) type UnwindRanges = Vec<(u32, u32)>;

pub(super) struct ExceptionRepair {
    pub(super) invalid: usize,
    pub(super) ranges: Option<UnwindRanges>,
}

impl ExceptionRepair {
    fn absent() -> Self {
        Self {
            invalid: 0,
            ranges: None,
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
) -> AppResult<ExceptionScan> {
    let layout = unwind_layout(output, model);
    let count = size / RUNTIME_FUNCTION_SIZE;
    let mut valid = Vec::<[u8; RUNTIME_FUNCTION_SIZE]>::with_capacity(count);
    let mut invalid = usize::from(!size.is_multiple_of(RUNTIME_FUNCTION_SIZE));
    for index in 0..count {
        let offset = file_offset
            .checked_add(index.saturating_mul(RUNTIME_FUNCTION_SIZE))
            .ok_or_else(|| AppError::new("runtime-function offset overflowed"))?;
        let Some(entry) = output.get(offset..offset.saturating_add(RUNTIME_FUNCTION_SIZE)) else {
            invalid = invalid.saturating_add(count.saturating_sub(index));
            break;
        };
        if runtime_function_is_valid(output, entry, model, layouts, header_size, layout) {
            let mut copy = [0u8; RUNTIME_FUNCTION_SIZE];
            copy.copy_from_slice(entry);
            valid.push(copy);
        } else {
            invalid = invalid.saturating_add(1);
        }
    }
    Ok(ExceptionScan { valid, invalid })
}

fn runtime_function_ranges(valid: &[[u8; RUNTIME_FUNCTION_SIZE]]) -> UnwindRanges {
    valid
        .iter()
        .filter_map(|entry| Some((read_u32(entry, 0).ok()?, read_u32(entry, 4).ok()?)))
        .collect()
}

fn write_valid_runtime_functions(
    output: &mut [u8],
    entry_offset: usize,
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
    for (index, entry) in valid.iter().enumerate() {
        let start = index.saturating_mul(RUNTIME_FUNCTION_SIZE);
        let end = start.saturating_add(RUNTIME_FUNCTION_SIZE);
        if let Some(slot) = destination.get_mut(start..end) {
            slot.copy_from_slice(entry);
        }
    }
    if valid.is_empty() {
        write_u32(output, entry_offset, 0)?;
        write_u32(output, entry_offset.saturating_add(4), 0)?;
        return Ok(());
    }
    let new_size = valid
        .len()
        .checked_mul(RUNTIME_FUNCTION_SIZE)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| AppError::new("exception-directory size overflowed"))?;
    write_u32(output, entry_offset.saturating_add(4), new_size)
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
    layout: UnwindLayout,
) -> bool {
    let Ok(begin) = read_u32(entry, 0) else {
        return false;
    };
    let Ok(end) = read_u32(entry, 4) else {
        return false;
    };
    let Ok(unwind) = read_u32(entry, 8) else {
        return false;
    };
    if begin >= end
        || !model.executable_rva(Rva(begin))
        || !model.executable_rva(Rva(end.saturating_sub(1)))
    {
        return false;
    }
    let Some(unwind_offset) = rva_to_file(unwind, layouts, header_size) else {
        return false;
    };
    let Some(first) = output.get(unwind_offset).copied() else {
        return false;
    };
    layout == UnwindLayout::Managed || matches!(first & 0x07, 1 | 2)
}
