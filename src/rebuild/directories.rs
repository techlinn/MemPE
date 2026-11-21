use super::{SectionLayout, rva_to_file};
use crate::pe::DEBUG_ENTRY_SIZE;
use crate::pe::DIRECTORY_COUNT;
use crate::pe::MAX_DEBUG_ENTRIES;
use crate::pe::RELOCATION_BLOCK_HEADER;
use crate::pe::bytes::{read_u16, read_u32, write_u16, write_u32};
use crate::pe::{
    BASERELOC_DIRECTORY, DEBUG_ADDRESS_OFFSET, DEBUG_DIRECTORY, DEBUG_POINTER_OFFSET,
    DELAY_IMPORT_DIRECTORY, DYNAMIC_BASE, FILE_CHARACTERISTICS_OFFSET, IAT_DIRECTORY,
    IMPORT_DIRECTORY, PeModel, RELOCATION_ABSOLUTE, RELOCATION_DIR64, RELOCATION_HIGH,
    RELOCATION_HIGH_ADJUST, RELOCATION_HIGHLOW, RELOCATION_LOW, RELOCS_STRIPPED,
    RESOURCE_DIRECTORY, SECURITY_DIRECTORY, TLS_DIRECTORY,
};
use crate::{AppError, AppResult};

const APPLIED_RELOCATIONS: [u16; 5] = [
    RELOCATION_HIGH,
    RELOCATION_LOW,
    RELOCATION_HIGHLOW,
    RELOCATION_HIGH_ADJUST,
    RELOCATION_DIR64,
];
const DIRECTORY_SIZE_FIELD: usize = 4; // in a data-directory entry
const SIZE_IGNORED_DIRECTORIES: [usize; 5] = [
    IMPORT_DIRECTORY,
    RESOURCE_DIRECTORY,
    TLS_DIRECTORY,
    IAT_DIRECTORY,
    DELAY_IMPORT_DIRECTORY,
]; // loader ignores Size

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
    pub(super) clamped: usize,
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

// unlike PeModel::directory, keeps an entry with only one field set
fn directory_entry(output: &[u8], model: &PeModel, index: usize) -> AppResult<Option<(u32, u32)>> {
    let Some(offset) = model.directory_offset(index) else {
        return Ok(None);
    };

    let size = read_u32(output, offset.saturating_add(DIRECTORY_SIZE_FIELD))?;
    Ok(Some((read_u32(output, offset)?, size)))
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
        let Some((rva, size)) = directory_entry(output, model, index)? else {
            continue;
        };

        if rva == 0 && size == 0 {
            continue;
        }

        let valid = index != SECURITY_DIRECTORY
            && directory_is_mapped(rva, size, layouts, header_size)
            && (index != BASERELOC_DIRECTORY
                || relocations_are_walkable(output, layouts, header_size, rva, size));

        let room = (!valid && size != 0 && SIZE_IGNORED_DIRECTORIES.contains(&index))
            .then(|| room_after(rva, layouts, header_size))
            .flatten();
        if let Some(room) = room {
            model
                .set_directory(output, index, rva as usize, room as usize)
                .ok_or_else(|| AppError::new("PE has no requested data-directory slot"))?;
            cleared.clamped = cleared.clamped.saturating_add(1);
            continue;
        }

        if !valid {
            model.clear_directory(output, index);
            cleared.record(index);
        }
    }

    Ok(cleared)
}

fn relocations_are_walkable(
    output: &[u8],
    layouts: &[SectionLayout<'_>],
    header_size: usize,
    rva: u32,
    size: u32,
) -> bool {
    let Some(start) = rva_to_file(rva, layouts, header_size) else {
        return false;
    };

    let end = start.saturating_add(size as usize);
    let mut cursor = start;

    // every block advances at least its header
    while cursor < end {
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

        let entries = block_size.saturating_sub(RELOCATION_BLOCK_HEADER) / 2;
        let mut index = 0usize;
        while index < entries {
            let offset = cursor
                .saturating_add(RELOCATION_BLOCK_HEADER)
                .saturating_add(index.saturating_mul(2));
            let Ok(entry) = read_u16(output, offset) else {
                return false;
            };

            let kind = entry >> 12;
            index = index.saturating_add(1);

            if kind == RELOCATION_ABSOLUTE {
                continue;
            }

            if !APPLIED_RELOCATIONS.contains(&kind) {
                return false;
            }

            if kind == RELOCATION_HIGH_ADJUST {
                if index >= entries {
                    return false;
                }

                index = index.saturating_add(1);
            }
        }

        cursor = cursor.saturating_add(block_size);
    }

    true
}

pub(super) fn repair_debug_directory(
    output: &mut [u8],
    model: &PeModel,
    layouts: &[SectionLayout<'_>],
    header_size: usize,
) -> AppResult<usize> {
    let Some(directory) = model.directory(output, DEBUG_DIRECTORY) else {
        return Ok(0);
    };

    let size = directory.size() as usize;
    if size < DEBUG_ENTRY_SIZE {
        return Ok(0);
    }

    let Some(table_offset) = rva_to_file(directory.rva().get(), layouts, header_size) else {
        return Ok(0);
    };

    let count = (size / DEBUG_ENTRY_SIZE).min(MAX_DEBUG_ENTRIES);
    let mut repaired = 0usize;
    for index in 0..count {
        let entry = table_offset
            .checked_add(index.saturating_mul(DEBUG_ENTRY_SIZE))
            .ok_or_else(|| AppError::new("debug-directory entry offset overflowed"))?;
        let pointer_offset = entry.saturating_add(DEBUG_POINTER_OFFSET);
        let (Ok(raw_rva), Ok(stored)) = (
            read_u32(output, entry.saturating_add(DEBUG_ADDRESS_OFFSET)),
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
    if model.directory(output, BASERELOC_DIRECTORY).is_some() {
        return Ok(false);
    }

    let file = model.nt_offset.saturating_add(FILE_CHARACTERISTICS_OFFSET);
    let stripped = read_u16(output, file)?;
    write_u16(output, file, stripped | RELOCS_STRIPPED)?;

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

fn room_after(rva: u32, layouts: &[SectionLayout<'_>], header_size: usize) -> Option<u32> {
    let start = rva as usize;
    let end = match start < header_size {
        true => header_size,
        false => layouts.iter().find_map(|layout| {
            let range = layout.virtual_range();
            range.contains(&start).then_some(range.end)
        })?,
    };

    u32::try_from(end.saturating_sub(start)).ok()
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
        let range = layout.virtual_range();
        start >= range.start && end <= range.end
    })
}
