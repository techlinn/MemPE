use crate::pe::PeModel;
use crate::pe::image::{read_u16, read_u32, write_u32};

const PAGE_MASK: u32 = 0xFFF;
const RELOCATION_BLOCK_HEADER: usize = 8;
const RELOCATION_BLOCK_SIZE_OFFSET: usize = 4;
const RELOCATION_KIND_SHIFT: u16 = 12;
const KNOWN_RELOCATION_KINDS: [u16; 5] = [0, 1, 2, 3, 10];
const EXPORT_DIRECTORY_SIZE: usize = 40;
const EXPORT_NAME_OFFSET: usize = 12;
const EXPORT_FUNCTION_COUNT_OFFSET: usize = 20;
const EXPORT_NAME_COUNT_OFFSET: usize = 24;
const EXPORT_FUNCTIONS_OFFSET: usize = 28;
const EXPORT_NAMES_OFFSET: usize = 32;
const EXPORT_ORDINALS_OFFSET: usize = 36;
const EXPORT_RVA_OFFSETS: [usize; 4] = [
    EXPORT_NAME_OFFSET,
    EXPORT_FUNCTIONS_OFFSET,
    EXPORT_NAMES_OFFSET,
    EXPORT_ORDINALS_OFFSET,
];
const EXPORT_TABLE_ENTRY_SIZE: usize = 4;
const RESOURCE_TABLE_SIZE: usize = 16;
const RESOURCE_NAMED_COUNT_OFFSET: usize = 12;
const RESOURCE_ID_COUNT_OFFSET: usize = 14;
const RESOURCE_ENTRY_SIZE: usize = 8;
const RESOURCE_ENTRY_TARGET_OFFSET: usize = 4;
const RESOURCE_DATA_ENTRY_SIZE: usize = 16;
const RESOURCE_SUBDIRECTORY: u32 = 0x8000_0000;
const MAX_RESOURCE_DEPTH: usize = 4;
const MAX_RESOURCE_ENTRIES: usize = 65_536;
pub(super) const DEBUG_ENTRY_SIZE: usize = 28;
const DEBUG_TIMESTAMP_OFFSET: usize = 4;
pub(super) const DEBUG_TYPE_OFFSET: usize = 12;
const DEBUG_SIZE_OFFSET: usize = 16;
const DEBUG_ADDRESS_OFFSET: usize = 20;
pub(super) const DEBUG_TYPE_CODEVIEW: u32 = 2;
const CODEVIEW_RSDS_HEADER: usize = 24; // signature, guid and age
const CODEVIEW_NB10_HEADER: usize = 16; // signature, offset, timestamp and age
const PDB_EXTENSION: &[u8] = b".pdb";
const MAX_PDB_PATH: usize = 1_024;

pub(super) enum Restoration {
    Restored,
    Absent,
    Failed,
    Lost,
}

pub(super) fn relocation_blocks(entries: &[(u32, u16)]) -> Option<Vec<u8>> {
    let mut sorted = entries.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut blocks = Vec::new();
    for page in sorted.chunk_by(|(left, _), (right, _)| left & !PAGE_MASK == right & !PAGE_MASK) {
        let mut words = page
            .iter()
            .map(|(rva, kind)| (kind << RELOCATION_KIND_SHIFT) | (rva & PAGE_MASK) as u16)
            .collect::<Vec<_>>();
        if !words.len().is_multiple_of(2) {
            words.push(0);
        }
        let size = u32::try_from(
            words
                .len()
                .checked_mul(2)?
                .checked_add(RELOCATION_BLOCK_HEADER)?,
        )
        .ok()?;
        blocks.extend_from_slice(&(page.first()?.0 & !PAGE_MASK).to_le_bytes());
        blocks.extend_from_slice(&size.to_le_bytes());
        for word in words {
            blocks.extend_from_slice(&word.to_le_bytes());
        }
    }
    Some(blocks)
}

pub(super) fn relocations_intact(bytes: &[u8], start: usize, size: usize) -> bool {
    let Some(table) = bytes.get(start..start.saturating_add(size)) else {
        return false;
    };
    if table.iter().all(|byte| *byte == 0) {
        return false;
    }
    let mut cursor = 0usize;
    while cursor < table.len() {
        let Ok(block_size) = read_u32(table, cursor.saturating_add(RELOCATION_BLOCK_SIZE_OFFSET))
        else {
            return false;
        };
        let block_size = block_size as usize;
        if block_size == 0 && read_u32(table, cursor).is_ok_and(|page| page == 0) {
            return true;
        }
        if block_size < RELOCATION_BLOCK_HEADER || !block_size.is_multiple_of(2) {
            return false;
        }
        let Some(words) = table
            .get(cursor.saturating_add(RELOCATION_BLOCK_HEADER)..cursor.saturating_add(block_size))
        else {
            return false;
        };
        let known = words.as_chunks::<2>().0.iter().all(|word| {
            KNOWN_RELOCATION_KINDS.contains(&(u16::from_le_bytes(*word) >> RELOCATION_KIND_SHIFT))
        });
        if !known {
            return false;
        }
        cursor = cursor.saturating_add(block_size);
    }
    true
}

pub(super) fn exports_intact(bytes: &[u8], start: usize) -> bool {
    let read = |offset: usize| read_u32(bytes, start.saturating_add(offset)).ok();
    let (Some(name), Some(functions), Some(table)) = (
        read(EXPORT_NAME_OFFSET),
        read(EXPORT_FUNCTION_COUNT_OFFSET),
        read(EXPORT_FUNCTIONS_OFFSET),
    ) else {
        return false;
    };
    functions > 0
        && table != 0
        && bytes
            .get(name as usize..)
            .and_then(|text| text.first())
            .is_some_and(|first| first.is_ascii_graphic())
}

pub(super) fn moved_export_directory(
    bytes: &[u8],
    packed: usize,
    size: usize,
    original: usize,
) -> Option<Vec<u8>> {
    if size < EXPORT_DIRECTORY_SIZE {
        return None;
    }
    let mut block = bytes.get(packed..packed.checked_add(size)?)?.to_vec();
    let packed_range = packed..packed.checked_add(size)?;
    let shift = |value: u32| -> Option<u32> {
        let value = value as usize;
        let moved = match packed_range.contains(&value) {
            true => value.checked_sub(packed)?.checked_add(original)?,
            false => value,
        };
        u32::try_from(moved).ok()
    };
    for field in EXPORT_RVA_OFFSETS {
        let moved = shift(read_u32(&block, field).ok()?)?;
        write_u32(&mut block, field, moved).ok()?;
    }

    let names = read_u32(&block, EXPORT_NAME_COUNT_OFFSET).ok()? as usize;
    let functions = read_u32(&block, EXPORT_FUNCTION_COUNT_OFFSET).ok()? as usize;
    for (table_field, count) in [
        (EXPORT_NAMES_OFFSET, names),
        (EXPORT_FUNCTIONS_OFFSET, functions),
    ] {
        let table = (read_u32(&block, table_field).ok()? as usize).checked_sub(original)?;
        for index in 0..count {
            let at = table.checked_add(index.checked_mul(EXPORT_TABLE_ENTRY_SIZE)?)?;
            let moved = shift(read_u32(&block, at).ok()?)?; // name strings and forwarder strings
            write_u32(&mut block, at, moved).ok()?;
        }
    }
    Some(block)
}

pub(super) struct ResourceTree {
    pub(super) structure_length: usize,
    pub(super) data_entries: Vec<usize>,
}

pub(super) fn walk_resources(bytes: &[u8], start: usize) -> Option<ResourceTree> {
    let mut tree = ResourceTree {
        structure_length: 0,
        data_entries: Vec::new(),
    };
    walk_resource_table(bytes, start, 0, 0, &mut tree)?;
    Some(tree)
}

fn walk_resource_table(
    bytes: &[u8],
    start: usize,
    table: usize,
    depth: usize,
    tree: &mut ResourceTree,
) -> Option<()> {
    if depth >= MAX_RESOURCE_DEPTH || tree.data_entries.len() >= MAX_RESOURCE_ENTRIES {
        return None;
    }
    let header = start.checked_add(table)?;
    let named =
        usize::from(read_u16(bytes, header.checked_add(RESOURCE_NAMED_COUNT_OFFSET)?).ok()?);
    let numbered =
        usize::from(read_u16(bytes, header.checked_add(RESOURCE_ID_COUNT_OFFSET)?).ok()?);
    let count = named.checked_add(numbered)?;
    let entries_end = table
        .checked_add(RESOURCE_TABLE_SIZE)?
        .checked_add(count.checked_mul(RESOURCE_ENTRY_SIZE)?)?;
    tree.structure_length = tree.structure_length.max(entries_end);

    for index in 0..count {
        let entry = header
            .checked_add(RESOURCE_TABLE_SIZE)?
            .checked_add(index.checked_mul(RESOURCE_ENTRY_SIZE)?)?;
        let name = read_u32(bytes, entry).ok()?;
        let target = read_u32(bytes, entry.checked_add(RESOURCE_ENTRY_TARGET_OFFSET)?).ok()?;
        if name & RESOURCE_SUBDIRECTORY != 0 {
            let string = (name & !RESOURCE_SUBDIRECTORY) as usize;
            let length = usize::from(read_u16(bytes, start.checked_add(string)?).ok()?);
            let string_end = string.checked_add(2)?.checked_add(length.checked_mul(2)?)?; // a u16 count of utf-16 units
            tree.structure_length = tree.structure_length.max(string_end);
        }
        let offset = (target & !RESOURCE_SUBDIRECTORY) as usize;
        if target & RESOURCE_SUBDIRECTORY != 0 {
            walk_resource_table(bytes, start, offset, depth.checked_add(1)?, tree)?;
        } else {
            let entry_end = offset.checked_add(RESOURCE_DATA_ENTRY_SIZE)?;
            tree.structure_length = tree.structure_length.max(entry_end);
            tree.data_entries.push(offset);
        }
    }
    Some(())
}

pub(super) fn resources_intact(bytes: &[u8], start: usize) -> bool {
    walk_resources(bytes, start).is_some_and(|tree| {
        !tree.data_entries.is_empty()
            && tree.data_entries.iter().all(|entry| {
                read_u32(bytes, start.saturating_add(*entry))
                    .is_ok_and(|rva| rva != 0 && (rva as usize) < bytes.len())
            })
    })
}

pub(super) struct CodeViewRecord {
    pub(super) rva: usize,
    pub(super) size: usize,
}

pub(super) fn find_codeview_record(bytes: &[u8]) -> Option<CodeViewRecord> {
    let mut found = None;
    for (signature, header) in [
        (b"RSDS", CODEVIEW_RSDS_HEADER),
        (b"NB10", CODEVIEW_NB10_HEADER),
    ] {
        for start in bytes
            .windows(signature.len())
            .enumerate()
            .filter(|(_, window)| window == signature)
            .map(|(start, _)| start)
        {
            let Some(size) = codeview_size(bytes, start, header) else {
                continue;
            };
            if found.is_some() {
                return None;
            }
            found = Some(CodeViewRecord { rva: start, size });
        }
    }
    found
}

fn codeview_size(bytes: &[u8], start: usize, header: usize) -> Option<usize> {
    let path_start = start.checked_add(header)?;
    let path = bytes.get(path_start..path_start.checked_add(MAX_PDB_PATH)?.min(bytes.len()))?;
    let length = path.iter().position(|byte| *byte == 0)?;
    let text = path.get(..length)?;
    let printable = text
        .iter()
        .all(|byte| byte.is_ascii_graphic() || *byte == b' ');
    let pdb = text
        .len()
        .checked_sub(PDB_EXTENSION.len())
        .and_then(|start| text.get(start..))
        .is_some_and(|extension| extension.eq_ignore_ascii_case(PDB_EXTENSION));
    (printable && pdb).then(|| header.saturating_add(length).saturating_add(1))
}

pub(super) fn codeview_entry(
    record: &CodeViewRecord,
    timestamp: u32,
) -> Option<[u8; DEBUG_ENTRY_SIZE]> {
    let mut entry = [0u8; DEBUG_ENTRY_SIZE];
    write_u32(&mut entry, DEBUG_TIMESTAMP_OFFSET, timestamp).ok()?;
    write_u32(&mut entry, DEBUG_TYPE_OFFSET, DEBUG_TYPE_CODEVIEW).ok()?;
    write_u32(
        &mut entry,
        DEBUG_SIZE_OFFSET,
        u32::try_from(record.size).ok()?,
    )
    .ok()?;
    write_u32(
        &mut entry,
        DEBUG_ADDRESS_OFFSET,
        u32::try_from(record.rva).ok()?,
    )
    .ok()?;
    Some(entry)
}

pub(super) fn is_free(restored: &[u8], destination: usize, content: &[u8]) -> bool {
    restored
        .get(destination..destination.saturating_add(content.len()))
        .is_some_and(|current| {
            current
                .iter()
                .zip(content)
                .all(|(byte, wanted)| *byte == 0 || byte == wanted)
        })
}

pub(super) fn place(restored: &mut [u8], destination: usize, content: &[u8]) -> Option<()> {
    if !is_free(restored, destination, content) {
        return None;
    }
    restored
        .get_mut(destination..destination.checked_add(content.len())?)?
        .copy_from_slice(content);
    Some(())
}

pub(super) fn set_directory(
    restored: &mut [u8],
    model: &PeModel,
    index: usize,
    rva: usize,
    size: usize,
) -> Option<()> {
    let offset = model.directory_offset(index).ok()??;
    write_u32(restored, offset, u32::try_from(rva).ok()?).ok()?;
    write_u32(restored, offset.checked_add(4)?, u32::try_from(size).ok()?).ok()
}

pub(super) fn clear_directory(restored: &mut [u8], model: &PeModel, index: usize) {
    let _ = set_directory(restored, model, index, 0, 0);
}
