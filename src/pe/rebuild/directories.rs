use super::{SectionLayout, rva_to_file};
use crate::pe::image::{read_u16, read_u32, write_u16, write_u32};
use crate::pe::{
    BASERELOC_DIRECTORY, DEBUG_DIRECTORY, DYNAMIC_BASE, PeKind, PeModel, RELOCATION_DIR64,
    RELOCATION_HIGHLOW, SECURITY_DIRECTORY,
};
use crate::{AppError, AppResult};

const RELOCATION_BLOCK_HEADER: usize = 8;
const RELOCATION_ABSOLUTE: u16 = 0;
const RELOCATION_HIGH: u16 = 1;
const RELOCATION_LOW: u16 = 2;
const MAX_RELOCATION_BLOCKS: usize = 65_536;
const DEBUG_ENTRY_SIZE: usize = 28;
const DEBUG_ENTRY_RAW_RVA: usize = 20;
const DEBUG_ENTRY_RAW_POINTER: usize = 24;
const MAX_DEBUG_ENTRIES: usize = 256;
const DIRECTORY_COUNT: usize = 16;

const DIRECTORY_NAMES: [&str; DIRECTORY_COUNT] = [
    "Export",
    "Import",
    "Resource",
    "Exception",
    "Certificate",
    "BaseReloc",
    "Debug",
    "Architecture",
    "GlobalPtr",
    "TLS",
    "LoadConfig",
    "BoundImport",
    "IAT",
    "DelayImport",
    "COMDescriptor",
    "Reserved",
];

const ROUTINE_DIRECTORIES: [usize; 1] = [SECURITY_DIRECTORY];

#[derive(Default)]
pub(super) struct ClearedDirectories {
    pub(super) total: usize,
    notable: Vec<&'static str>,
}

impl ClearedDirectories {
    pub(super) fn record(&mut self, index: usize) {
        self.total = self.total.saturating_add(1);

        if is_notable_directory(index) {
            self.notable.push(directory_name(index));
        }
    }

    pub(super) fn notable_names(&self) -> Vec<String> {
        self.notable
            .iter()
            .map(|name| (*name).to_string())
            .collect()
    }
}

pub(super) fn write_directory(
    output: &mut [u8],
    model: &PeModel,
    index: usize,
    rva: u32,
    size: u32,
) -> AppResult<()> {
    let offset = model
        .directory_offset(index)?
        .ok_or_else(|| AppError::new("PE has no requested data-directory slot"))?;
    write_u32(output, offset, rva)?;
    write_u32(output, offset.saturating_add(4), size)
}

pub(super) fn clear_directory(
    output: &mut [u8],
    model: &PeModel,
    index: usize,
) -> AppResult<usize> {
    let Some(offset) = model.directory_offset(index)? else {
        return Ok(0);
    };

    let was_set =
        read_u32(output, offset)? != 0 || read_u32(output, offset.saturating_add(4))? != 0;
    write_u32(output, offset, 0)?;
    write_u32(output, offset.saturating_add(4), 0)?;

    Ok(usize::from(was_set))
}

fn directory_name(index: usize) -> &'static str {
    DIRECTORY_NAMES.get(index).copied().unwrap_or("Unknown")
}

fn is_notable_directory(index: usize) -> bool {
    !ROUTINE_DIRECTORIES.contains(&index)
}

pub(super) fn clear_bad_directories(
    output: &mut [u8],
    model: &PeModel,
    layouts: &[SectionLayout<'_>],
    header_size: usize,
) -> AppResult<ClearedDirectories> {
    let mut cleared = ClearedDirectories::default();

    for index in 0..model.directory_count {
        let entry_offset = model
            .directory_offset(index)?
            .ok_or_else(|| AppError::new("data-directory slot is missing"))?;
        let rva = read_u32(output, entry_offset)?;
        let size = read_u32(output, entry_offset.saturating_add(4))?;

        if rva == 0 && size == 0 {
            continue;
        }

        let valid = index != SECURITY_DIRECTORY
            && directory_is_mapped(rva, size, layouts, header_size)
            && (index != BASERELOC_DIRECTORY
                || relocations_are_walkable(output, model, layouts, header_size, rva, size));
        if !valid {
            write_directory(output, model, index, 0, 0)?;
            cleared.record(index);
        }
    }

    Ok(cleared)
}

fn relocations_are_walkable(
    output: &[u8],
    model: &PeModel,
    layouts: &[SectionLayout<'_>],
    header_size: usize,
    rva: u32,
    size: u32,
) -> bool {
    let Some(start) = rva_to_file(rva, layouts, header_size) else {
        return false;
    };

    let end = start.saturating_add(size as usize);
    let expected: &[u16] = match model.kind {
        PeKind::Pe32 => &[RELOCATION_HIGHLOW, RELOCATION_HIGH, RELOCATION_LOW],
        PeKind::Pe32Plus => &[RELOCATION_DIR64],
    };

    let mut cursor = start;
    let mut fixups = 0usize;
    for _block in 0..MAX_RELOCATION_BLOCKS {
        if cursor >= end {
            return fixups > 0;
        }

        let (Ok(page), Ok(block_size)) = (
            read_u32(output, cursor),
            read_u32(output, cursor.saturating_add(4)),
        ) else {
            return false;
        };

        let block_size = block_size as usize;
        if block_size < RELOCATION_BLOCK_HEADER
            || !block_size.is_multiple_of(2)
            || cursor.saturating_add(block_size) > end
            || rva_to_file(page, layouts, header_size).is_none()
        {
            return false;
        }

        for index in 0..block_size.saturating_sub(RELOCATION_BLOCK_HEADER) / 2 {
            let offset = cursor
                .saturating_add(RELOCATION_BLOCK_HEADER)
                .saturating_add(index.saturating_mul(2));
            let Ok(entry) = read_u16(output, offset) else {
                return false;
            };

            let kind = entry >> 12;

            if kind == RELOCATION_ABSOLUTE {
                continue;
            }

            if !expected.contains(&kind) {
                return false;
            }

            fixups = fixups.saturating_add(1);
        }

        cursor = cursor.saturating_add(block_size);
    }

    false
}

pub(super) fn repair_debug_directory(
    output: &mut [u8],
    model: &PeModel,
    layouts: &[SectionLayout<'_>],
    header_size: usize,
) -> AppResult<usize> {
    if DEBUG_DIRECTORY >= model.directory_count {
        return Ok(0);
    }

    let entry_offset = model
        .directory_offset(DEBUG_DIRECTORY)?
        .ok_or_else(|| AppError::new("debug-directory slot is missing"))?;
    let rva = read_u32(output, entry_offset)?;
    let size = read_u32(output, entry_offset.saturating_add(4))? as usize;

    if rva == 0 || size < DEBUG_ENTRY_SIZE {
        return Ok(0);
    }

    let Some(table_offset) = rva_to_file(rva, layouts, header_size) else {
        return Ok(0);
    };

    let count = (size / DEBUG_ENTRY_SIZE).min(MAX_DEBUG_ENTRIES);
    let mut repaired = 0usize;
    for index in 0..count {
        let entry = table_offset
            .checked_add(index.saturating_mul(DEBUG_ENTRY_SIZE))
            .ok_or_else(|| AppError::new("debug-directory entry offset overflowed"))?;
        let pointer_offset = entry.saturating_add(DEBUG_ENTRY_RAW_POINTER);
        let (Ok(raw_rva), Ok(stored)) = (
            read_u32(output, entry.saturating_add(DEBUG_ENTRY_RAW_RVA)),
            read_u32(output, pointer_offset),
        ) else {
            break;
        };

        let pointer = (raw_rva != 0)
            .then(|| rva_to_file(raw_rva, layouts, header_size))
            .flatten()
            .and_then(|offset| u32::try_from(offset).ok())
            .unwrap_or(0);
        if stored != pointer {
            write_u32(output, pointer_offset, pointer)?;
            repaired = repaired.saturating_add(1);
        }
    }

    Ok(repaired)
}

pub(super) fn clear_dynamic_base(output: &mut [u8], model: &PeModel) -> AppResult<bool> {
    if let Some(offset) = model.directory_offset(BASERELOC_DIRECTORY)?
        && read_u32(output, offset)? != 0
        && read_u32(output, offset.saturating_add(4))? != 0
    {
        return Ok(false);
    }

    let characteristics = read_u16(output, model.dll_characteristics_offset)?;

    if characteristics & DYNAMIC_BASE == 0 {
        return Ok(false);
    }

    write_u16(
        output,
        model.dll_characteristics_offset,
        characteristics & !DYNAMIC_BASE,
    )?;

    Ok(true)
}

fn directory_is_mapped(
    rva: u32,
    size: u32,
    layouts: &[SectionLayout<'_>],
    header_size: usize,
) -> bool {
    if size == 0 {
        return false;
    }

    let start = rva as usize;
    let Some(end) = start.checked_add(size as usize) else {
        return false;
    };

    if end <= header_size {
        return true;
    }

    layouts.iter().any(|layout| {
        let section_start = layout.model.virtual_address.get() as usize;
        let section_end = section_start.saturating_add(layout.source_length);
        start >= section_start && end <= section_end
    })
}
