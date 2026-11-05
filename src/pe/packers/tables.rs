use std::collections::HashMap;
use std::ops::Range;

use super::{FreshImage, ImportedFunction, ModuleImports, PackerImports};
use crate::pe::image::{read_pointer, read_u16, read_u32, write_u16, write_u32, write_u64};
use crate::pe::parse::{parse_disk_image, parse_memory_image};
use crate::pe::{
    BASERELOC_DIRECTORY, IAT_DIRECTORY, IMPORT_DIRECTORY, PeKind, PeModel, RELOCATION_DIR64,
    RELOCATION_HIGHLOW, RESOURCE_DIRECTORY, Rva, SECTION_HEADER_SIZE, TLS_DIRECTORY,
};

const PAGE_MASK: u32 = 0xFFF;
pub(super) const RELOCATION_BLOCK_HEADER: usize = 8;
pub(super) const RELOCATION_BLOCK_SIZE_OFFSET: usize = 4;
pub(super) const MAX_RELOCATION_BLOCK: usize = 0x10000;
pub(super) const SECTION_COUNT_OFFSET: usize = 6; // from the nt signature
pub(super) const SECTION_RVA_OFFSET: usize = 12;
pub(super) const SECTION_CHARACTERISTICS_OFFSET: usize = 36;
const SECTION_VIRTUAL_SIZE_OFFSET: usize = 8;
const SECTION_RAW_SIZE_OFFSET: usize = 16;
const SECTION_RAW_POINTER_OFFSET: usize = 20;
pub(super) const CODE_SECTION: u32 = 0x6000_0020; // read, execute, code
pub(super) const DATA_SECTION: u32 = 0xC000_0040; // read, write, initialized data
pub(super) const RESOURCE_SECTION: u32 = 0x4000_0040; // read, initialized data
pub(super) const RELOCATION_SECTION: u32 = 0x4200_0040; // read, discardable, initialized data
pub(super) const RESOURCE_DATA_SIZE_OFFSET: usize = 4;
const TLS_DIRECTORY_PE32: usize = 24;
const TLS_DIRECTORY_PE32_PLUS: usize = 40;
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
const EXPORT_ORDINAL_SIZE: usize = 2;
const RESOURCE_TABLE_SIZE: usize = 16;
const RESOURCE_NAMED_COUNT_OFFSET: usize = 12;
const RESOURCE_ID_COUNT_OFFSET: usize = 14;
const RESOURCE_ENTRY_SIZE: usize = 8;
const RESOURCE_ENTRY_TARGET_OFFSET: usize = 4;
const RESOURCE_DATA_ENTRY_SIZE: usize = 16;
const RESOURCE_SUBDIRECTORY: u32 = 0x8000_0000;
const MAX_RESOURCE_DEPTH: usize = 4;
const MAX_RESOURCE_ENTRIES: usize = 65_536;
const LINKER_LEAF_ALIGNMENT: usize = 8;
const RESOURCE_LEAF_ALIGNMENTS: [usize; 2] = [LINKER_LEAF_ALIGNMENT, 4]; // windows only needs 4
pub(super) const RESOURCE_SIZE_ALIGNMENT: usize = 8; // msvc pads the resource section to 8 bytes
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
const MAX_NAME_LENGTH: usize = 4_096;
const DELAY_DESCRIPTOR_SIZE: usize = 32;
const DELAY_ATTRIBUTES_RVA_BASED: u32 = 1;
const DELAY_NAME_OFFSET: usize = 4;
const DELAY_HANDLE_OFFSET: usize = 8;
const DELAY_IAT_OFFSET: usize = 12;
const DELAY_NAMES_OFFSET: usize = 16;
const MAX_DELAY_DESCRIPTORS: usize = 256;
const MAX_DLL_NAME: usize = 256;
const LOAD_CONFIG_TIMESTAMP_OFFSET: usize = 4;
const LOAD_CONFIG_COOKIE_PE32: usize = 0x3C;
const LOAD_CONFIG_COOKIE_PE32_PLUS: usize = 0x58;
const LOAD_CONFIG_HANDLERS_PE32: usize = 0x40; // safeseh table, then its count
const MAX_SAFESEH_HANDLERS: u32 = 0x10000;
const MAX_LOAD_CONFIG_SIZE: u32 = 0x400;
pub(super) const FIRST_SECTION_RVA: usize = 0x1000;
const SCAN_STEP: usize = 4;
const DIRECTORY_COUNT: usize = 16;
const RELOCATION_OFFSET_MASK: u16 = 0xFFF;
pub(super) const IMPORT_DESCRIPTOR_SIZE: usize = 20;
pub(super) const IMPORT_NAME_OFFSET: usize = 12;
pub(super) const IMPORT_IAT_OFFSET: usize = 16;
pub(super) const MAX_IMPORT_DESCRIPTORS: usize = 4_096;
pub(super) const MAX_THUNKS: usize = 65_536;
pub(super) const THUNK_SIZE: usize = 4; // only PE32 packers hand over an import list
pub(super) const ORDINAL_FLAG: u32 = 0x8000_0000;
pub(super) const HINT_SIZE: usize = 2; // a name entry starts with its export hint

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

pub(super) fn export_functions(bytes: &[u8], start: usize) -> Option<Vec<usize>> {
    let count = read_u32(bytes, start.checked_add(EXPORT_FUNCTION_COUNT_OFFSET)?).ok()? as usize;
    let table = read_u32(bytes, start.checked_add(EXPORT_FUNCTIONS_OFFSET)?).ok()? as usize;
    (0..count.min(MAX_RESOURCE_ENTRIES))
        .map(|index| {
            let at = table.checked_add(index.checked_mul(EXPORT_TABLE_ENTRY_SIZE)?)?;
            Some(read_u32(bytes, at).ok()? as usize)
        })
        .collect()
}

pub(super) fn linker_export_layout(
    bytes: &[u8],
    copy: usize,
    forwarders: &[(usize, String)],
    known_start: Option<usize>,
) -> Option<(usize, Vec<u8>)> {
    let field = |offset: usize| Some(read_u32(bytes, copy.checked_add(offset)?).ok()? as usize);
    let functions = export_functions(bytes, copy)?;
    let name_count = field(EXPORT_NAME_COUNT_OFFSET)?.min(MAX_RESOURCE_ENTRIES);
    let (names, ordinals) = (field(EXPORT_NAMES_OFFSET)?, field(EXPORT_ORDINALS_OFFSET)?);
    let module = read_c_string(bytes, field(EXPORT_NAME_OFFSET)?)?.0;

    let mut exported = Vec::with_capacity(name_count); // name, its function index, its forwarder
    for index in 0..name_count {
        let name = read_u32(bytes, names.checked_add(index.checked_mul(4)?)?).ok()? as usize;
        let function = read_u16(bytes, ordinals.checked_add(index.checked_mul(2)?)?).ok()?;
        let forwarder = functions
            .get(usize::from(function))
            .and_then(|rva| forwarders.iter().find(|(at, _)| at == rva));
        exported.push((read_c_string(bytes, name)?.0, function, forwarder));
    }

    let placed = exported
        .iter()
        .filter(|(_, _, forwarder)| forwarder.is_some())
        .count();
    (placed == forwarders.len()).then_some(())?;

    let name_table = EXPORT_DIRECTORY_SIZE.checked_add(functions.len().checked_mul(4)?)?;
    let ordinal_table = name_table.checked_add(name_count.checked_mul(4)?)?;
    let module_offset = ordinal_table.checked_add(name_count.checked_mul(2)?)?;
    let mut cursor = module_offset.checked_add(module.len())?.checked_add(1)?;
    let mut name_offsets = Vec::with_capacity(name_count);
    let mut inferred = None;
    let mut forwarder_offsets = Vec::new(); // function index and where its forwarder string lands
    for (name, function, forwarder) in &exported {
        name_offsets.push(cursor);
        cursor = cursor.checked_add(name.len())?.checked_add(1)?;

        if let Some((rva, target)) = forwarder {
            forwarder_offsets.push((usize::from(*function), cursor));
            if known_start.is_none() {
                let here = rva.checked_sub(cursor)?; // each forwarder still sits where the linker put it
                (*inferred.get_or_insert(here) == here).then_some(())?;
            }
            cursor = cursor.checked_add(target.len())?.checked_add(1)?;
        }
    }

    let start = known_start.or(inferred)?;
    let mut block = bytes
        .get(copy..copy.checked_add(EXPORT_DIRECTORY_SIZE)?)?
        .to_vec();
    for (offset, value) in [
        (EXPORT_NAME_OFFSET, module_offset),
        (EXPORT_FUNCTIONS_OFFSET, EXPORT_DIRECTORY_SIZE),
        (EXPORT_NAMES_OFFSET, name_table),
        (EXPORT_ORDINALS_OFFSET, ordinal_table),
    ] {
        write_u32(
            &mut block,
            offset,
            u32::try_from(start.checked_add(value)?).ok()?,
        )
        .ok()?;
    }

    for (index, rva) in functions.iter().enumerate() {
        let rva = match forwarder_offsets
            .iter()
            .find(|(function, _)| *function == index)
        {
            Some((_, offset)) => start.checked_add(*offset)?,
            None => *rva,
        };
        block.extend_from_slice(&u32::try_from(rva).ok()?.to_le_bytes());
    }

    for offset in &name_offsets {
        block.extend_from_slice(
            &u32::try_from(start.checked_add(*offset)?)
                .ok()?
                .to_le_bytes(),
        );
    }

    for (_, function, _) in &exported {
        block.extend_from_slice(&function.to_le_bytes());
    }

    block.extend_from_slice(module.as_bytes());
    block.push(0);

    for (name, _, forwarder) in &exported {
        block.extend_from_slice(name.as_bytes());
        block.push(0);

        if let Some((_, target)) = forwarder {
            block.extend_from_slice(target.as_bytes());
            block.push(0);
        }
    }

    Some((start, block))
}

pub(super) fn linker_export_start(bytes: &[u8], copy: usize) -> Option<usize> {
    let field = |offset: usize| Some(read_u32(bytes, copy.checked_add(offset)?).ok()? as usize);
    let tables = field(EXPORT_FUNCTION_COUNT_OFFSET)?
        .checked_mul(EXPORT_TABLE_ENTRY_SIZE)?
        .checked_add(
            field(EXPORT_NAME_COUNT_OFFSET)?
                .checked_mul(EXPORT_TABLE_ENTRY_SIZE + EXPORT_ORDINAL_SIZE)?,
        )?
        .checked_add(EXPORT_DIRECTORY_SIZE)?;

    field(EXPORT_NAME_OFFSET)?.checked_sub(tables) // the linker writes the module name right after them
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
            let string_end = string.checked_add(2)?.checked_add(length.checked_mul(2)?)?;
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

pub(super) fn return_moved_leaves(
    restored: &mut [u8],
    tree_start: usize,
    region: Range<usize>,
    original_end: usize,
) -> Restoration {
    let Some(tree) = walk_resources(restored, tree_start) else {
        return Restoration::Failed;
    };

    let leaves = tree
        .data_entries
        .iter()
        .filter_map(|entry| {
            let at = tree_start.checked_add(*entry)?;
            let rva = read_u32(restored, at).ok()? as usize;
            let size =
                read_u32(restored, at.checked_add(RESOURCE_DATA_SIZE_OFFSET)?).ok()? as usize;
            Some((at, rva, size))
        })
        .collect::<Vec<_>>();
    let moved = leaves
        .iter()
        .filter(|(_, rva, _)| *rva >= original_end)
        .copied()
        .collect::<Vec<_>>();
    if moved.is_empty() {
        return Restoration::Absent;
    }

    let mut used = leaves
        .iter()
        .filter(|(_, rva, _)| *rva < original_end)
        .map(|(_, rva, size)| (*rva, rva.saturating_add(*size)))
        .collect::<Vec<_>>();
    used.push((tree_start, tree_start.saturating_add(tree.structure_length)));

    for (entry, rva, size) in moved {
        let Some(data) = restored
            .get(rva..rva.saturating_add(size))
            .map(<[u8]>::to_vec)
        else {
            return Restoration::Failed;
        };

        let overlaps = |at: usize| {
            used.iter()
                .any(|(start, end)| at < *end && *start < at.saturating_add(size))
        };

        let Some(destination) = RESOURCE_LEAF_ALIGNMENTS.iter().find_map(|alignment| {
            (region.start..region.end.saturating_sub(size))
                .step_by(*alignment)
                .find(|at| !overlaps(*at) && is_free(restored, *at, &data))
        }) else {
            return Restoration::Failed;
        };

        let written = restored
            .get_mut(destination..destination.saturating_add(size))
            .map(|slot| slot.copy_from_slice(&data))
            .and_then(|()| write_u32(restored, entry, u32::try_from(destination).ok()?).ok());
        if written.is_none() {
            return Restoration::Failed;
        }

        used.push((destination, destination.saturating_add(size)));
    }

    Restoration::Restored
}

pub(super) fn lay_out_resources(
    restored: &mut [u8],
    model: &PeModel,
    packed_root: usize,
    section: Range<usize>,
) -> Option<()> {
    let mut tree = linker_resource_layout(restored, packed_root)?;
    let leaves = tree
        .data_entries
        .iter()
        .map(|entry| {
            let rva = read_u32(&tree.bytes, *entry).ok()? as usize;
            let size = read_u32(&tree.bytes, entry.checked_add(RESOURCE_DATA_SIZE_OFFSET)?).ok()?;
            restored
                .get(rva..rva.checked_add(size as usize)?)
                .map(<[u8]>::to_vec)
        })
        .collect::<Option<Vec<_>>>()?;

    let mut cursor = section.start.checked_add(tree.bytes.len())?;
    let mut placed = Vec::with_capacity(leaves.len());
    for (entry, data) in tree.data_entries.iter().zip(&leaves) {
        cursor = cursor.checked_next_multiple_of(LINKER_LEAF_ALIGNMENT)?;
        write_u32(&mut tree.bytes, *entry, u32::try_from(cursor).ok()?).ok()?;
        placed.push(cursor - section.start);
        cursor = cursor.checked_add(data.len())?;
    }
    (cursor <= section.end).then_some(())?;

    let region = restored.get_mut(section.clone())?;
    region.fill(0);
    region
        .get_mut(..tree.bytes.len())?
        .copy_from_slice(&tree.bytes);
    for (offset, data) in placed.into_iter().zip(&leaves) {
        region
            .get_mut(offset..offset + data.len())?
            .copy_from_slice(data);
    }

    let size = (cursor - section.start).checked_next_multiple_of(RESOURCE_SIZE_ALIGNMENT)?;
    set_directory(restored, model, RESOURCE_DIRECTORY, section.start, size)
}

pub(super) struct LinkerTree {
    pub(super) bytes: Vec<u8>,
    pub(super) data_entries: Vec<usize>,
}

pub(super) fn linker_resource_layout(bytes: &[u8], start: usize) -> Option<LinkerTree> {
    let entries_of = |table: usize| -> Option<Vec<(u32, u32)>> {
        let header = start.checked_add(table)?;
        let named = read_u16(bytes, header.checked_add(RESOURCE_NAMED_COUNT_OFFSET)?).ok()?;
        let numbered = read_u16(bytes, header.checked_add(RESOURCE_ID_COUNT_OFFSET)?).ok()?;

        (0..usize::from(named) + usize::from(numbered))
            .map(|index| {
                let entry =
                    header.checked_add(RESOURCE_TABLE_SIZE + index * RESOURCE_ENTRY_SIZE)?;
                let target = entry.checked_add(RESOURCE_ENTRY_TARGET_OFFSET)?;
                Some((read_u32(bytes, entry).ok()?, read_u32(bytes, target).ok()?))
            })
            .collect()
    };

    let mut tables = vec![(0usize, entries_of(0)?)]; // breadth first, the order msvc writes them in
    let mut next = 0;

    while let Some((_, entries)) = tables.get(next) {
        let children = entries
            .iter()
            .filter(|(_, target)| target & RESOURCE_SUBDIRECTORY != 0)
            .map(|(_, target)| (target & !RESOURCE_SUBDIRECTORY) as usize)
            .collect::<Vec<_>>();

        for child in children {
            (tables.len() < MAX_RESOURCE_ENTRIES).then_some(())?;
            tables.push((child, entries_of(child)?));
        }
        next += 1;
    }

    let mut table_offsets = HashMap::new();
    let mut length = 0usize;
    for (table, entries) in &tables {
        table_offsets.insert(*table, length);
        length = length.checked_add(RESOURCE_TABLE_SIZE + entries.len() * RESOURCE_ENTRY_SIZE)?;
    }

    let mut leaves = Vec::new();
    collect_leaves(&tables, 0, 0, &mut leaves)?; // depth first, unlike the tables

    let mut leaf_offsets = HashMap::new();
    for leaf in &leaves {
        leaf_offsets.insert(*leaf, length);
        length = length.checked_add(RESOURCE_DATA_ENTRY_SIZE)?;
    }

    let mut string_offsets = HashMap::new();
    let mut strings = Vec::new();
    for (name, _) in tables.iter().flat_map(|(_, entries)| entries) {
        if name & RESOURCE_SUBDIRECTORY == 0 {
            continue;
        }

        let at = start.checked_add((name & !RESOURCE_SUBDIRECTORY) as usize)?;
        let units = usize::from(read_u16(bytes, at).ok()?);
        let string = bytes.get(at..at.checked_add(2 + units * 2)?)?;

        if !string_offsets.contains_key(string) {
            string_offsets.insert(string, length);
            strings.push(string);
            length = length.checked_add(string.len())?;
        }
    }

    let mut layout = vec![0u8; length];
    let named_string = |name: u32| -> Option<u32> {
        let at = start.checked_add((name & !RESOURCE_SUBDIRECTORY) as usize)?;
        let units = usize::from(read_u16(bytes, at).ok()?);
        let offset = string_offsets.get(bytes.get(at..at.checked_add(2 + units * 2)?)?)?;
        Some(u32::try_from(*offset).ok()? | RESOURCE_SUBDIRECTORY)
    };

    for (table, entries) in &tables {
        let to = *table_offsets.get(table)?;
        let from = start.checked_add(*table)?;
        layout
            .get_mut(to..to + RESOURCE_TABLE_SIZE)?
            .copy_from_slice(bytes.get(from..from.checked_add(RESOURCE_TABLE_SIZE)?)?);

        for (index, (name, target)) in entries.iter().enumerate() {
            let name = match name & RESOURCE_SUBDIRECTORY {
                0 => *name,
                _ => named_string(*name)?,
            };
            let offset = (target & !RESOURCE_SUBDIRECTORY) as usize;
            let target = match target & RESOURCE_SUBDIRECTORY {
                0 => u32::try_from(*leaf_offsets.get(&offset)?).ok()?,
                _ => u32::try_from(*table_offsets.get(&offset)?).ok()? | RESOURCE_SUBDIRECTORY,
            };

            let entry = to + RESOURCE_TABLE_SIZE + index * RESOURCE_ENTRY_SIZE;
            write_u32(&mut layout, entry, name).ok()?;
            write_u32(&mut layout, entry + RESOURCE_ENTRY_TARGET_OFFSET, target).ok()?;
        }
    }

    for leaf in &leaves {
        let to = *leaf_offsets.get(leaf)?;
        let from = start.checked_add(*leaf)?;
        layout
            .get_mut(to..to + RESOURCE_DATA_ENTRY_SIZE)?
            .copy_from_slice(bytes.get(from..from.checked_add(RESOURCE_DATA_ENTRY_SIZE)?)?);
    }

    for string in strings {
        let to = *string_offsets.get(string)?;
        layout
            .get_mut(to..to + string.len())?
            .copy_from_slice(string);
    }

    let data_entries = leaves
        .iter()
        .map(|leaf| leaf_offsets.get(leaf).copied())
        .collect::<Option<Vec<_>>>()?;

    Some(LinkerTree {
        bytes: layout,
        data_entries,
    })
}

fn collect_leaves(
    tables: &[(usize, Vec<(u32, u32)>)],
    table: usize,
    depth: usize,
    leaves: &mut Vec<usize>,
) -> Option<()> {
    (depth < MAX_RESOURCE_DEPTH).then_some(())?;
    let (_, entries) = tables.iter().find(|(offset, _)| *offset == table)?;

    for (_, target) in entries {
        let offset = (target & !RESOURCE_SUBDIRECTORY) as usize;
        match target & RESOURCE_SUBDIRECTORY {
            0 => leaves.push(offset),
            _ => collect_leaves(tables, offset, depth + 1, leaves)?,
        }
    }

    Some(())
}

pub(super) fn map_disk_image(file: &[u8], end: usize) -> Option<Vec<u8>> {
    let disk = parse_disk_image(file).ok()?;
    let mut image = vec![0u8; end];

    for section in disk.model().sections() {
        let rva = section.virtual_address().as_usize();
        let start = section.raw_pointer as usize;
        let length = (section.raw_size as usize).min(section.span() as usize);
        let raw = file.get(start..start.checked_add(length)?)?;
        if let Some(slot) = image.get_mut(rva..rva.saturating_add(raw.len())) {
            slot.copy_from_slice(raw);
        }
    }

    Some(image)
}

pub(super) trait OriginalImage {
    fn original_u32(&mut self, rva: usize) -> Option<u32>;
    fn original_string(&mut self, rva: usize) -> Option<String>;
}

impl OriginalImage for &[u8] {
    fn original_u32(&mut self, rva: usize) -> Option<u32> {
        read_u32(self, rva).ok()
    }

    fn original_string(&mut self, rva: usize) -> Option<String> {
        read_c_string(self, rva).map(|(name, _)| name)
    }
}

pub(super) fn imports_from_original(
    restored: &mut [u8],
    model: &PeModel,
    import_rva: usize,
    original: &mut impl OriginalImage,
) -> Option<PackerImports> {
    let modules = listed_imports(import_rva, original)?;
    iat_filled(restored, &modules).then_some(())?;
    apply_listed_imports(restored, model, modules)
}

pub(super) fn listed_imports(
    import_rva: usize,
    original: &mut impl OriginalImage,
) -> Option<Vec<ModuleImports>> {
    let mut modules = Vec::new();
    for index in 0..MAX_IMPORT_DESCRIPTORS {
        let descriptor = import_rva.checked_add(index.checked_mul(IMPORT_DESCRIPTOR_SIZE)?)?;
        let lookup = original.original_u32(descriptor)? as usize;
        let name = original.original_u32(descriptor.checked_add(IMPORT_NAME_OFFSET)?)? as usize;
        let iat = original.original_u32(descriptor.checked_add(IMPORT_IAT_OFFSET)?)? as usize;

        if name == 0 && iat == 0 {
            break;
        }

        let module = original.original_string(name)?;
        let source = match lookup {
            0 => iat, // borland linkers leave the names in the iat itself
            _ => lookup,
        };

        let mut functions = Vec::new();
        for slot in 0..MAX_THUNKS {
            let entry =
                original.original_u32(source.checked_add(slot.checked_mul(THUNK_SIZE)?)?)?;

            if entry == 0 {
                break;
            }

            functions.push(match entry & ORDINAL_FLAG {
                0 => ImportedFunction::Name(
                    original.original_string((entry as usize).checked_add(HINT_SIZE)?)?,
                ),
                _ => ImportedFunction::Ordinal(entry as u16),
            });
        }

        modules.push(ModuleImports {
            module,
            first_thunk: u32::try_from(iat).ok()?,
            functions,
        });
    }

    Some(modules)
}

pub(super) fn iat_filled(restored: &[u8], modules: &[ModuleImports]) -> bool {
    modules.iter().all(|module| {
        let iat = module.first_thunk as usize;
        let filled = |slot: usize| {
            read_u32(restored, iat.saturating_add(slot * THUNK_SIZE)).is_ok_and(|value| value != 0)
        };
        (0..module.functions.len()).all(filled) && !filled(module.functions.len())
    })
}

pub(super) fn apply_listed_imports(
    restored: &mut [u8],
    model: &PeModel,
    modules: Vec<ModuleImports>,
) -> Option<PackerImports> {
    let tables = modules
        .iter()
        .map(|module| (module.first_thunk as usize, module.functions.len()));
    let (first, span) = iat_span(tables, THUNK_SIZE)?;
    clear_directory(restored, model, IMPORT_DIRECTORY);
    set_directory(restored, model, IAT_DIRECTORY, first, span)?;

    Some(PackerImports::Listed(modules))
}

pub(super) struct SectionPiece {
    pub(super) name: [u8; 8],
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) characteristics: u32,
}

pub(super) fn replace_first_section(
    restored: &mut [u8],
    model: &PeModel,
    pieces: &[SectionPiece],
) -> Option<()> {
    let mut table = Vec::new();
    for piece in pieces {
        let mut header = [0u8; SECTION_HEADER_SIZE];
        header[..piece.name.len()].copy_from_slice(&piece.name);

        let size = u32::try_from(piece.end.checked_sub(piece.start)?).ok()?;
        let rva = u32::try_from(piece.start).ok()?;
        for (offset, value) in [
            (SECTION_VIRTUAL_SIZE_OFFSET, size),
            (SECTION_RVA_OFFSET, rva),
            (SECTION_RAW_SIZE_OFFSET, size),
            (SECTION_RAW_POINTER_OFFSET, rva),
            (SECTION_CHARACTERISTICS_OFFSET, piece.characteristics),
        ] {
            write_u32(&mut header, offset, value).ok()?;
        }

        table.extend_from_slice(&header);
    }

    let packed = model.sections().first()?;
    let start = packed.virtual_address().as_usize();
    let first = packed.header_offset;
    let rest = model
        .sections()
        .len()
        .checked_sub(1)?
        .checked_mul(SECTION_HEADER_SIZE)?;
    let old_end = first.checked_add(SECTION_HEADER_SIZE)?.checked_add(rest)?;
    let new_end = first.checked_add(table.len())?.checked_add(rest)?;
    let headers_end = read_u32(restored, model.size_of_headers_offset).ok()? as usize;
    let grown = restored.get(headers_end.max(old_end)..new_end.max(headers_end));

    (new_end <= start && grown.is_some_and(|tail| tail.iter().all(|byte| *byte == 0)))
        .then_some(())?;

    if new_end > headers_end {
        let headers_end = new_end.checked_next_multiple_of(model.file_alignment as usize)?;
        write_u32(
            restored,
            model.size_of_headers_offset,
            u32::try_from(headers_end).ok()?,
        )
        .ok()?;
    }

    let others = restored
        .get(first.checked_add(SECTION_HEADER_SIZE)?..old_end)?
        .to_vec();
    table.extend_from_slice(&others);
    restored.get_mut(first..new_end)?.copy_from_slice(&table);

    let count = u16::try_from(table.len() / SECTION_HEADER_SIZE).ok()?;
    write_u16(
        restored,
        model.nt_offset.checked_add(SECTION_COUNT_OFFSET)?,
        count,
    )
    .ok()
}

pub(super) fn fresh_image(
    memory: &[u8],
    restored: &[u8],
    pristine: &[u8],
    pristine_base: usize,
    base: usize,
    end: usize,
    left_alone: &[Range<usize>],
) -> Option<FreshImage> {
    let image = parse_memory_image(restored).ok()?;
    let model = image.model();
    let mut pristine = pristine.get(..end.min(pristine.len()))?.to_vec();

    let delta = base.wrapping_sub(pristine_base);
    if delta != 0 {
        rebase(&mut pristine, restored, model, delta)?;
    }

    let entry = read_u32(restored, model.entry_point_offset).ok()?;
    let mut kept = (0..DIRECTORY_COUNT)
        .filter_map(|index| model.directory(restored, index).ok().flatten())
        .map(|directory| {
            let start = directory.rva().as_usize();
            start..start.saturating_add(directory.size() as usize)
        })
        .chain(left_alone.iter().cloned())
        .collect::<Vec<_>>(); // tables mempe rebuilt or the loader fills in stay as restored

    let mut fresh = restored.to_vec();
    let mut changed = 0usize;

    for section in model.sections() {
        let start = section.virtual_address().as_usize();
        let span = start..start.saturating_add(section.span() as usize);
        if section.contains_rva(Rva(entry)) {
            kept.push(span); // the code may carry the packer's own jumps in the file
            continue;
        }

        let stop = span
            .end
            .min(pristine.len())
            .min(memory.len())
            .min(fresh.len());
        for at in span.start.max(FIRST_SECTION_RVA)..stop {
            let untouched = restored[at] == memory[at];
            if untouched
                && pristine[at] != memory[at]
                && !kept.iter().any(|range| range.contains(&at))
            {
                fresh[at] = pristine[at];
                changed += 1;
            }
        }
    }

    (changed > 0).then_some(FreshImage {
        bytes: fresh,
        changed,
    })
}

fn rebase(bytes: &mut [u8], restored: &[u8], model: &PeModel, delta: usize) -> Option<()> {
    relocate(bytes, restored, model, |value, _| value.wrapping_add(delta))
}

pub(super) fn relocate(
    bytes: &mut [u8],
    restored: &[u8],
    model: &PeModel,
    adjust: impl Fn(usize, PeKind) -> usize,
) -> Option<()> {
    let directory = model.directory(restored, BASERELOC_DIRECTORY).ok()??;
    let start = directory.rva().as_usize();
    let table = restored.get(start..start.checked_add(directory.size() as usize)?)?;

    let mut cursor = 0usize;
    while cursor + RELOCATION_BLOCK_HEADER <= table.len() {
        let page = read_u32(table, cursor).ok()? as usize;
        let size = read_u32(table, cursor + RELOCATION_BLOCK_SIZE_OFFSET).ok()? as usize;
        if page == 0 || size < RELOCATION_BLOCK_HEADER {
            break;
        }

        let words = table.get(cursor + RELOCATION_BLOCK_HEADER..cursor.checked_add(size)?)?;
        for word in words.as_chunks::<2>().0 {
            let word = u16::from_le_bytes(*word);
            let at = page + usize::from(word & RELOCATION_OFFSET_MASK);

            let kind = match word >> RELOCATION_KIND_SHIFT {
                RELOCATION_HIGHLOW => PeKind::Pe32,
                RELOCATION_DIR64 => PeKind::Pe32Plus,
                _ => continue,
            };

            let Ok(value) = read_pointer(bytes, at, kind) else {
                continue;
            };
            let moved = adjust(value, kind);
            let _ = match kind {
                PeKind::Pe32 => write_u32(bytes, at, moved as u32),
                PeKind::Pe32Plus => write_u64(bytes, at, moved as u64),
            };
        }

        cursor += size;
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

pub(super) fn iat_span(
    tables: impl IntoIterator<Item = (usize, usize)>, // first slot and slot count of each table
    width: usize,
) -> Option<(usize, usize)> {
    let mut first = usize::MAX;
    let mut end = 0;
    for (start, slots) in tables {
        first = first.min(start);
        end = end.max(start.checked_add(slots.checked_add(1)?.checked_mul(width)?)?); // plus the terminator
    }

    (first < end).then(|| (first, end - first))
}

pub(super) fn set_tls_directory(restored: &mut [u8], model: &PeModel, rva: usize) -> Option<()> {
    let size = match model.kind() {
        PeKind::Pe32 => TLS_DIRECTORY_PE32,
        PeKind::Pe32Plus => TLS_DIRECTORY_PE32_PLUS,
    };

    set_directory(restored, model, TLS_DIRECTORY, rva, size)
}

pub(super) fn clear_directory(restored: &mut [u8], model: &PeModel, index: usize) {
    let _ = set_directory(restored, model, index, 0, 0);
}

pub(super) fn find_delay_directory(bytes: &[u8], end: usize) -> Option<(usize, usize)> {
    unique(
        (FIRST_SECTION_RVA..end)
            .step_by(SCAN_STEP)
            .filter_map(|at| {
                let count = delay_descriptor_count(bytes, at, end)?;
                Some((
                    at,
                    count.checked_add(1)?.checked_mul(DELAY_DESCRIPTOR_SIZE)?,
                ))
            }),
    )
}

fn delay_descriptor_count(bytes: &[u8], start: usize, end: usize) -> Option<usize> {
    let in_image = |rva: u32| (FIRST_SECTION_RVA..end).contains(&(rva as usize));

    for index in 0..MAX_DELAY_DESCRIPTORS {
        let at = start.checked_add(index.checked_mul(DELAY_DESCRIPTOR_SIZE)?)?;
        let descriptor = bytes.get(at..at.checked_add(DELAY_DESCRIPTOR_SIZE)?)?;

        if index > 0 && descriptor.iter().all(|byte| *byte == 0) {
            return Some(index);
        }

        let field = |offset: usize| read_u32(descriptor, offset).ok();
        let valid = field(0) == Some(DELAY_ATTRIBUTES_RVA_BASED)
            && field(DELAY_HANDLE_OFFSET).is_some_and(in_image)
            && field(DELAY_IAT_OFFSET).is_some_and(in_image)
            && field(DELAY_NAMES_OFFSET).is_some_and(in_image)
            && field(DELAY_NAME_OFFSET).is_some_and(|name| is_dll_name(bytes, name as usize));
        if !valid {
            return None;
        }
    }

    None
}

fn is_dll_name(bytes: &[u8], at: usize) -> bool {
    let Some(text) = bytes.get(at..at.saturating_add(MAX_DLL_NAME).min(bytes.len())) else {
        return false;
    };

    let Some(length) = text.iter().position(|byte| *byte == 0) else {
        return false;
    };

    let name = &text[..length];
    name.iter().all(u8::is_ascii_graphic)
        && name.len() > 4
        && name[name.len() - 4..].eq_ignore_ascii_case(b".dll")
}

pub(super) fn find_load_config(
    bytes: &[u8],
    kind: PeKind,
    base: usize,
    end: usize,
) -> Option<usize> {
    let cookie_offset = match kind {
        PeKind::Pe32 => LOAD_CONFIG_COOKIE_PE32,
        PeKind::Pe32Plus => LOAD_CONFIG_COOKIE_PE32_PLUS,
    };

    let width = kind.pointer_width();
    let in_image = |value: usize| (base..base.saturating_add(end)).contains(&value);
    unique((FIRST_SECTION_RVA..end).step_by(SCAN_STEP).filter(|at| {
        let size = read_u32(bytes, *at).unwrap_or(0);
        let cookie = read_pointer(bytes, at.saturating_add(cookie_offset), kind).ok();
        size as usize > cookie_offset.saturating_add(width)
            && size <= MAX_LOAD_CONFIG_SIZE
            && size.is_multiple_of(4)
            && read_u32(bytes, at.saturating_add(LOAD_CONFIG_TIMESTAMP_OFFSET)) == Ok(0)
            && cookie.is_some_and(in_image)
            && (matches!(kind, PeKind::Pe32Plus) || safeseh_fits(bytes, *at, in_image))
    }))
}

fn safeseh_fits(bytes: &[u8], at: usize, in_image: impl Fn(usize) -> bool) -> bool {
    let table = read_u32(bytes, at.saturating_add(LOAD_CONFIG_HANDLERS_PE32)).unwrap_or(u32::MAX);
    let count =
        read_u32(bytes, at.saturating_add(LOAD_CONFIG_HANDLERS_PE32 + 4)).unwrap_or(u32::MAX);
    (table == 0 || in_image(table as usize)) && count <= MAX_SAFESEH_HANDLERS
}

pub(super) fn find_original_tls(
    bytes: &[u8],
    copy: usize,
    kind: PeKind,
    end: usize,
) -> Option<usize> {
    let width = kind.pointer_width();
    let callbacks = width.checked_mul(3)?;
    let length = width.checked_mul(4)?.checked_add(8)?;
    let wanted = bytes.get(copy..copy.checked_add(length)?)?;
    let (before, after) = (wanted.get(..callbacks)?, wanted.get(callbacks + width..)?);
    unique((FIRST_SECTION_RVA..end).step_by(SCAN_STEP).filter(|at| {
        *at != copy
            && bytes.get(*at..at.saturating_add(callbacks)) == Some(before)
            && bytes.get(at.saturating_add(callbacks + width)..at.saturating_add(length))
                == Some(after)
    }))
}

pub(super) fn find_tls_by_template(
    bytes: &[u8],
    copy: usize,
    kind: PeKind,
    base: usize,
    end: usize,
) -> Option<usize> {
    let width = kind.pointer_width();
    let template = |at: usize, limit: usize| -> Option<(usize, usize)> {
        let image = |pointer: usize| pointer.checked_sub(base).filter(|rva| *rva < limit);
        let start = image(read_pointer(bytes, at, kind).ok()?)?;
        let stop = image(read_pointer(bytes, at.checked_add(width)?, kind).ok()?)?;
        image(read_pointer(bytes, at.checked_add(width * 2)?, kind).ok()?)?;
        (stop > start).then_some((start, stop))
    };

    let (start, stop) = template(copy, bytes.len())?;
    let wanted = bytes.get(start..stop)?;
    unique((FIRST_SECTION_RVA..end).step_by(SCAN_STEP).filter(|at| {
        *at != copy
            && template(*at, end).is_some_and(|(other_start, other_stop)| {
                other_start != start && bytes.get(other_start..other_stop) == Some(wanted)
            })
    }))
}

fn unique<T>(mut found: impl Iterator<Item = T>) -> Option<T> {
    let first = found.next()?;
    found.next().is_none().then_some(first)
}

pub(super) fn read_c_string(bytes: &[u8], at: usize) -> Option<(String, usize)> {
    let tail = bytes.get(at..)?;
    let length = tail
        .iter()
        .take(MAX_NAME_LENGTH)
        .position(|byte| *byte == 0)?;
    let text = std::str::from_utf8(tail.get(..length)?).ok()?;
    (!text.is_empty()).then(|| (text.to_owned(), at.saturating_add(length).saturating_add(1)))
}
