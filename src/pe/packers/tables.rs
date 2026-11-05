use std::collections::{HashMap, HashSet};
use std::ops::Range;

use super::{FreshImage, ImportedFunction, ModuleImports, PackerImports, PackerReport};
use crate::pe::image::{read_pointer, read_u16, read_u32, write_u16, write_u32, write_u64};
use crate::pe::parse::{parse_disk_image, parse_memory_image};
use crate::pe::{
    BASERELOC_DIRECTORY, DEBUG_DIRECTORY, DELAY_IMPORT_DIRECTORY, IAT_DIRECTORY, IMPORT_DIRECTORY,
    LOAD_CONFIG_DIRECTORY, PeKind, PeModel, RELOCATION_DIR64, RELOCATION_HIGHLOW,
    RESOURCE_DIRECTORY, Rva, SECTION_HEADER_SIZE, TLS_DIRECTORY,
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
pub(super) const READ_ONLY_SECTION: u32 = 0x4000_0040;
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
const RT_ICON: u32 = 3;
const RT_GROUP_ICON: u32 = 14;
const ICON_GROUP_HEADER: usize = 6;
const ICON_GROUP_COUNT_OFFSET: usize = 4;
const ICON_GROUP_ENTRY_SIZE: usize = 14;
const ICON_ENTRY_PLANES_OFFSET: usize = 4;
const ICON_ENTRY_BITS_OFFSET: usize = 6;
const ICON_ENTRY_SIZE_OFFSET: usize = 8;
const ICON_ENTRY_ID_OFFSET: usize = 12;
const PNG_SIGNATURE: &[u8] = b"\x89PNG";
const PNG_WIDTH_OFFSET: usize = 16;
const PNG_HEIGHT_OFFSET: usize = 20;
const PNG_DEPTH_OFFSET: usize = 24;
const PNG_COLOR_TYPE_OFFSET: usize = 25;
const BITMAP_WIDTH_OFFSET: usize = 4;
const BITMAP_HEIGHT_OFFSET: usize = 8; // an icon bitmap counts its mask too, so twice the height
const BITMAP_PLANES_OFFSET: usize = 12;
const BITMAP_BITS_OFFSET: usize = 14;
const FULL_ICON_SIZE: u32 = 256; // stored as 0 in a one byte field
const MAX_RESOURCE_DEPTH: usize = 4;
const MAX_RESOURCE_ENTRIES: usize = 65_536;
const LINKER_LEAF_ALIGNMENT: usize = 8;
const RESOURCE_LEAF_ALIGNMENTS: [usize; 2] = [LINKER_LEAF_ALIGNMENT, 4]; // windows only needs 4
pub(super) const RESOURCE_SIZE_ALIGNMENT: usize = 8; // msvc pads the resource section to 8 bytes
const BORLAND_LEAF_ALIGNMENT: usize = 4;
const VISUAL_BASIC_FIRST_LEAF_ALIGNMENT: usize = 16;
const LINKER_VERSION_OFFSET: usize = 0x1A;
const BORLAND_LINKER: [u8; 2] = [2, 25];
const VISUAL_BASIC_RUNTIMES: [&str; 2] = ["msvbvm60.dll", "msvbvm50.dll"];
const BORLAND_RESOURCE: &[u8] = b"D\0V\0C\0L\0A\0L\0"; // every delphi and c++builder program carries this rcdata
pub(super) const DEBUG_ENTRY_SIZE: usize = 28;
const DEBUG_TIMESTAMP_OFFSET: usize = 4;
pub(super) const DEBUG_TYPE_OFFSET: usize = 12;
pub(super) const DEBUG_SIZE_OFFSET: usize = 16;
pub(super) const DEBUG_ADDRESS_OFFSET: usize = 20;
pub(super) const DEBUG_TYPE_CODEVIEW: u32 = 2;
const DEBUG_TYPE_POGO: u32 = 13;
const POGO_SIGNATURES: [&[u8]; 5] = [b"\0\0\0\0", b"\0UGP", b"\0IGP", b"\0OGP", b"GCTL"]; // none, PGU, PGI, PGO and LTCG
const POGO_RECORDS: usize = 4;
const POGO_FIRST_NAME: usize = 12;
const POGO_RECORD_HEADER: usize = 8;
const MAX_POGO_NAME: usize = 64;
const MAX_POGO_PARTS: usize = 4_096;
const MIN_POGO_PARTS: usize = 3;
const TLS_PART: &[u8] = b".rdata$T"; // where msvc places _tls_used, the tls directory
const READ_ONLY_PARTS: [&[u8]; 9] = [
    b".rdata", b".idata", b".CRT", b".00cfg", b".rtc", b".xdata", b".edata", b".didat", b".tls",
];
const WRITABLE_PARTS: [&[u8]; 2] = [b".data", b".bss"];
const SECTION_NAMES: [&[u8]; 3] = [b".text", b".rdata", b".data"]; // a section holding one of these parts takes its name, code first
const MAX_DEBUG_TYPE: u32 = 20; // the highest image_debug_type windows defines
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
const LOAD_CONFIG_DIRECTORY_SIZE: usize = 0x40; // msvc PE32 value, the loader reads the struct's own size
pub(super) const FIRST_SECTION_RVA: usize = 0x1000;
const SCAN_STEP: usize = 4;
const MODULE_ALIGNMENT: u32 = 0x1_0000;
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
    pub(super) kinds: Vec<[u32; 2]>, // type and name ids
}

pub(super) fn walk_resources(bytes: &[u8], start: usize) -> Option<ResourceTree> {
    let mut tree = ResourceTree {
        structure_length: 0,
        data_entries: Vec::new(),
        kinds: Vec::new(),
    };

    let mut budget = MAX_RESOURCE_ENTRIES;
    walk_resource_table(bytes, start, 0, (0, [0; 2]), &mut tree, &mut budget)?;
    Some(tree)
}

fn walk_resource_table(
    bytes: &[u8],
    start: usize,
    table: usize,
    (depth, path): (usize, [u32; 2]),
    tree: &mut ResourceTree,
    budget: &mut usize,
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
        *budget = budget.checked_sub(1)?;
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
            let mut below = path;
            if let Some(level) = below.get_mut(depth) {
                *level = name;
            }
            walk_resource_table(
                bytes,
                start,
                offset,
                (depth.checked_add(1)?, below),
                tree,
                budget,
            )?;
        } else {
            let entry_end = offset.checked_add(RESOURCE_DATA_ENTRY_SIZE)?;
            tree.structure_length = tree.structure_length.max(entry_end);
            tree.data_entries.push(offset);
            tree.kinds.push(path);
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

#[derive(Clone, Copy, PartialEq)]
pub(super) enum ResourceLayout {
    Microsoft,
    Borland,
    VisualBasic,
}

pub(super) fn resource_layout<'a>(
    bytes: &[u8],
    model: &PeModel,
    mut modules: impl Iterator<Item = &'a str>,
) -> ResourceLayout {
    if modules.any(|module| {
        VISUAL_BASIC_RUNTIMES
            .iter()
            .any(|runtime| module.eq_ignore_ascii_case(runtime))
    }) {
        return ResourceLayout::VisualBasic;
    }
    let at = model.nt_offset.saturating_add(LINKER_VERSION_OFFSET);
    let linker = bytes.get(at..at.saturating_add(BORLAND_LINKER.len()));
    let named = || {
        let root = model
            .directory(bytes, RESOURCE_DIRECTORY)
            .ok()??
            .rva()
            .as_usize();
        let tree = linker_resource_layout(bytes, root)?;
        Some(
            tree.bytes
                .windows(BORLAND_RESOURCE.len())
                .any(|name| name == BORLAND_RESOURCE),
        )
    };
    match linker == Some(&BORLAND_LINKER[..]) || named().unwrap_or(false) {
        true => ResourceLayout::Borland,
        false => ResourceLayout::Microsoft,
    }
}

pub(super) fn lay_out_resources(
    restored: &mut [u8],
    model: &PeModel,
    packed_root: usize,
    section: Range<usize>,
    layout: ResourceLayout,
    pristine: Option<&[u8]>,
) -> Option<()> {
    let kept_size = model
        .directory(restored, RESOURCE_DIRECTORY)
        .ok()
        .flatten()
        .map(|directory| directory.size() as usize);
    let mut tree = linker_resource_layout(restored, packed_root)?;
    let leaves = tree
        .data_entries
        .iter()
        .map(|entry| {
            let rva = read_u32(&tree.bytes, *entry).ok()? as usize;
            let size = read_u32(&tree.bytes, entry.checked_add(RESOURCE_DATA_SIZE_OFFSET)?).ok()?;
            pristine
                .unwrap_or(restored)
                .get(rva..rva.checked_add(size as usize)?)
                .map(<[u8]>::to_vec)
        })
        .collect::<Option<Vec<_>>>()?;

    let (first_alignment, alignment) = match layout {
        ResourceLayout::Microsoft => (LINKER_LEAF_ALIGNMENT, LINKER_LEAF_ALIGNMENT),
        ResourceLayout::Borland => (BORLAND_LEAF_ALIGNMENT, BORLAND_LEAF_ALIGNMENT),
        ResourceLayout::VisualBasic => (VISUAL_BASIC_FIRST_LEAF_ALIGNMENT, BORLAND_LEAF_ALIGNMENT),
    };
    let order: Vec<usize> = match layout {
        ResourceLayout::VisualBasic => (0..leaves.len()).rev().collect(), // vb6 writes them last entry first
        _ => (0..leaves.len()).collect(),
    };
    let mut cursor = section
        .start
        .checked_add(tree.bytes.len())?
        .checked_next_multiple_of(first_alignment)?;
    let mut placed = vec![0; leaves.len()];
    for index in order {
        cursor = cursor.checked_next_multiple_of(alignment)?;
        let entry = *tree.data_entries.get(index)?;
        write_u32(&mut tree.bytes, entry, u32::try_from(cursor).ok()?).ok()?;
        placed[index] = cursor - section.start;
        cursor = cursor.checked_add(leaves.get(index)?.len())?;
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

    let used = cursor - section.start;
    let size = match kept_size {
        Some(kept) if kept >= used && section.start.checked_add(kept)? <= section.end => kept, // fsg keeps the original size
        _ => used.checked_next_multiple_of(RESOURCE_SIZE_ALIGNMENT)?,
    };
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
    let mut seen = HashSet::from([0usize]);
    let mut total = tables[0].1.len();
    let mut next = 0;

    while let Some((_, entries)) = tables.get(next) {
        let children = entries
            .iter()
            .filter(|(_, target)| target & RESOURCE_SUBDIRECTORY != 0)
            .map(|(_, target)| (target & !RESOURCE_SUBDIRECTORY) as usize)
            .collect::<Vec<_>>();

        for child in children {
            seen.insert(child).then_some(())?; // a linker never shares or loops a table
            let entries = entries_of(child)?;
            total = total.checked_add(entries.len())?;
            (total <= MAX_RESOURCE_ENTRIES).then_some(())?;
            tables.push((child, entries));
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
    let by_offset = tables
        .iter()
        .map(|(offset, entries)| (*offset, entries.as_slice()))
        .collect::<HashMap<_, _>>();
    collect_leaves(&by_offset, 0, 0, &mut leaves)?; // depth first, unlike the tables

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
    tables: &HashMap<usize, &[(u32, u32)]>,
    table: usize,
    depth: usize,
    leaves: &mut Vec<usize>,
) -> Option<()> {
    (depth < MAX_RESOURCE_DEPTH).then_some(())?;
    let entries = tables.get(&table)?;

    for (_, target) in entries.iter() {
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
    let headers = read_u32(file, disk.model().size_of_headers_offset).ok()? as usize;
    let mapped_headers = headers.min(file.len()).min(end);
    image
        .get_mut(..mapped_headers)?
        .copy_from_slice(file.get(..mapped_headers)?);

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

pub(super) struct SectionHints {
    pub(super) code: Option<usize>,
    pub(super) code_end: Option<usize>,
    pub(super) constants: Option<usize>,
    pub(super) relocations: Option<usize>,
    pub(super) resources: Option<usize>,
}

pub(super) fn name_sections(
    mut starts: Vec<usize>,
    end: usize,
    hints: &SectionHints,
) -> Vec<SectionPiece> {
    starts.sort_unstable();
    starts.dedup();
    starts
        .iter()
        .enumerate()
        .map(|(index, &start)| {
            let piece_end = starts.get(index + 1).copied().unwrap_or(end);
            let inside =
                |rva: Option<usize>| rva.is_some_and(|rva| (start..piece_end).contains(&rva));
            let code =
                inside(hints.code) || hints.code_end.is_some_and(|code_end| start < code_end);
            let (name, characteristics) = if code {
                (*b".text\0\0\0", CODE_SECTION)
            } else if hints.relocations == Some(start) {
                (*b".reloc\0\0", RELOCATION_SECTION)
            } else if inside(hints.resources) {
                (*b".rsrc\0\0\0", RESOURCE_SECTION)
            } else if hints.constants == Some(start) {
                (*b".rdata\0\0", READ_ONLY_SECTION)
            } else {
                (*b".data\0\0\0", DATA_SECTION)
            };

            SectionPiece {
                name,
                start,
                end: piece_end,
                characteristics,
            }
        })
        .collect()
}

#[derive(Clone, Copy)]
pub(super) struct LinkerBounds {
    pub(super) code_end: usize,
    pub(super) data: Option<usize>,
}

pub(super) fn linker_bounds(restored: &[u8], model: &PeModel, code: usize) -> Option<LinkerBounds> {
    let packed = model.sections().first()?;
    let start = packed.virtual_address().as_usize();
    let end = start.checked_add(packed.span() as usize)?;
    let alignment = model.section_alignment as usize;
    let code_start = read_u32(restored, model.base_of_code_offset).ok()? as usize; // mpress and fsg keep these
    let code_size = read_u32(restored, model.size_of_code_offset).ok()? as usize;
    let code_end = code_start
        .checked_add(code_size)?
        .checked_next_multiple_of(alignment)?;
    let fits = code_start == start
        && code_end > start
        && code_end < end
        && (start..code_end).contains(&code);
    fits.then_some(())?;

    let data = (model.kind() == PeKind::Pe32)
        .then(|| read_u32(restored, model.base_of_code_offset.checked_add(4)?).ok())
        .flatten()
        .map(|rva| rva as usize)
        .filter(|rva| rva.is_multiple_of(alignment) && (code_end..end).contains(rva));
    Some(LinkerBounds { code_end, data })
}

pub(super) fn split_merged_section(
    restored: &mut [u8],
    model: &PeModel,
    hints: &SectionHints,
    data: Option<usize>,
    image_end: Option<usize>,
) -> Option<()> {
    let packed = model.sections().first()?;
    let start = packed.virtual_address().as_usize();
    let packed_end = start.checked_add(packed.span() as usize)?;
    let alignment = model.section_alignment as usize;
    let code = hints.code.unwrap_or(start);
    let bounds = linker_bounds(restored, model, code)?;
    let end = image_end
        .filter(|end| {
            end.is_multiple_of(alignment) && (bounds.code_end + 1..packed_end).contains(end)
        })
        .unwrap_or(packed_end);

    let inner = [
        hints.constants,
        bounds.data,
        data,
        hints.relocations,
        hints.resources,
    ]
    .into_iter()
    .flatten()
    .filter(|rva| rva.is_multiple_of(alignment) && (bounds.code_end..end).contains(rva));
    let starts = [start, bounds.code_end].into_iter().chain(inner).collect();
    let hints = SectionHints {
        code: Some(code),
        code_end: Some(bounds.code_end),
        ..*hints
    };
    let mut pieces = name_sections(starts, end, &hints);
    if end < packed_end {
        pieces.push(SectionPiece {
            name: [0; 8],
            start: end,
            end: packed_end,
            characteristics: DATA_SECTION,
        });
    }
    replace_first_section(restored, model, &pieces)
}

pub(super) fn lowest_moved_leaf(restored: &[u8], model: &PeModel, end: usize) -> Option<usize> {
    let root = model
        .directory(restored, RESOURCE_DIRECTORY)
        .ok()??
        .rva()
        .as_usize();
    let tree = walk_resources(restored, root)?;
    tree.data_entries
        .iter()
        .filter_map(|entry| Some(read_u32(restored, root.checked_add(*entry)?).ok()? as usize))
        .filter(|rva| *rva < end)
        .min()
}

pub(super) fn repair_icon_groups(restored: &mut [u8], model: &PeModel) -> Restoration {
    let Ok(Some(directory)) = model.directory(restored, RESOURCE_DIRECTORY) else {
        return Restoration::Absent;
    };

    let root = directory.rva().as_usize();
    let icons = typed_leaves(restored, root, RT_ICON);
    let groups = typed_leaves(restored, root, RT_GROUP_ICON);
    let by_id = icons
        .iter()
        .map(|(id, rva, size)| (*id, (*rva, *size)))
        .collect::<HashMap<_, _>>();
    let icon_at = |id: u32| by_id.get(&id).copied();
    let entry_at = |group: usize, index: usize| {
        group
            .checked_add(ICON_GROUP_HEADER)?
            .checked_add(index.checked_mul(ICON_GROUP_ENTRY_SIZE)?)
    };
    let fits = |bytes: &[u8], entry: usize| {
        let id = read_u16(bytes, entry + ICON_ENTRY_ID_OFFSET).ok()?;
        let size = read_u32(bytes, entry + ICON_ENTRY_SIZE_OFFSET).ok()?;
        icon_at(u32::from(id))
            .filter(|(_, icon_size)| *icon_size == size as usize)
            .map(|_| id)
    };

    let mut broken = Vec::new();
    let mut referenced = HashSet::new();
    let mut budget = MAX_RESOURCE_ENTRIES;
    for (_, group, size) in &groups {
        let count = usize::from(read_u16(restored, group + ICON_GROUP_COUNT_OFFSET).unwrap_or(0));
        budget = match budget.checked_sub(count) {
            Some(left) => left,
            None => return Restoration::Failed,
        };
        for index in 0..count {
            let Some(entry) = entry_at(*group, index)
                .filter(|entry| entry + ICON_GROUP_ENTRY_SIZE <= group + size)
            else {
                return Restoration::Failed;
            };
            match fits(restored, entry) {
                Some(id) => {
                    referenced.insert(u32::from(id));
                }
                None => broken.push(entry),
            }
        }
    }
    if broken.is_empty() {
        return Restoration::Absent;
    }

    let mut spare = icons
        .iter()
        .filter(|(id, ..)| !referenced.contains(id))
        .map(|(id, rva, size)| (*id, *rva, *size))
        .collect::<Vec<_>>(); // the linker numbers icons in the order the groups list them
    spare.sort_unstable();
    if spare.len() < broken.len() {
        return Restoration::Failed;
    }

    for (entry, (id, rva, size)) in broken.into_iter().zip(spare) {
        let rebuilt = restored
            .get(rva..rva.saturating_add(size))
            .and_then(|icon| icon_group_entry(icon, id, size));
        let written = rebuilt.and_then(|rebuilt| {
            restored
                .get_mut(entry..entry.checked_add(ICON_GROUP_ENTRY_SIZE)?)?
                .copy_from_slice(&rebuilt);
            Some(())
        });
        if written.is_none() {
            return Restoration::Failed;
        }
    }

    Restoration::Restored
}

fn typed_leaves(bytes: &[u8], root: usize, kind: u32) -> Vec<(u32, usize, usize)> {
    let Some(tree) = walk_resources(bytes, root) else {
        return Vec::new();
    };

    tree.data_entries
        .iter()
        .zip(&tree.kinds)
        .filter(|(_, [type_id, _])| *type_id == kind)
        .filter_map(|(entry, [_, id])| {
            let at = root.checked_add(*entry)?;
            let rva = read_u32(bytes, at).ok()? as usize;
            let size = read_u32(bytes, at.checked_add(RESOURCE_DATA_SIZE_OFFSET)?).ok()? as usize;
            Some((*id, rva, size))
        })
        .collect()
}

fn icon_group_entry(icon: &[u8], id: u32, size: usize) -> Option<[u8; ICON_GROUP_ENTRY_SIZE]> {
    let byte_size = |value: u32| match value {
        FULL_ICON_SIZE => Some(0),
        _ => u8::try_from(value).ok(),
    };
    let big_endian = |at: usize| Some(u32::from_be_bytes(icon.get(at..at + 4)?.try_into().ok()?));
    let (width, height, colors, planes, bits) = if icon.starts_with(PNG_SIGNATURE) {
        let channels = match icon.get(PNG_COLOR_TYPE_OFFSET)? {
            0 | 3 => 1,
            2 => 3,
            4 => 2,
            6 => 4,
            _ => return None,
        };
        let bits = u16::from(*icon.get(PNG_DEPTH_OFFSET)?) * channels;
        (
            big_endian(PNG_WIDTH_OFFSET)?,
            big_endian(PNG_HEIGHT_OFFSET)?,
            0,
            1,
            bits,
        )
    } else {
        let bits = read_u16(icon, BITMAP_BITS_OFFSET).ok()?;
        let colors = if bits < 8 { 1u8 << bits } else { 0 };
        (
            read_u32(icon, BITMAP_WIDTH_OFFSET).ok()?,
            read_u32(icon, BITMAP_HEIGHT_OFFSET).ok()? / 2,
            colors,
            read_u16(icon, BITMAP_PLANES_OFFSET).ok()?,
            bits,
        )
    };

    let mut entry = [0u8; ICON_GROUP_ENTRY_SIZE];
    entry[0] = byte_size(width)?;
    entry[1] = byte_size(height)?;
    entry[2] = colors;
    write_u16(&mut entry, ICON_ENTRY_PLANES_OFFSET, planes).ok()?;
    write_u16(&mut entry, ICON_ENTRY_BITS_OFFSET, bits).ok()?;
    write_u32(
        &mut entry,
        ICON_ENTRY_SIZE_OFFSET,
        u32::try_from(size).ok()?,
    )
    .ok()?;
    write_u16(&mut entry, ICON_ENTRY_ID_OFFSET, u16::try_from(id).ok()?).ok()?;
    Some(entry)
}

pub(super) fn restore_moved_resources(
    restored: &mut [u8],
    model: &PeModel,
    sections: &[Range<usize>],
    end: usize,
    layout: ResourceLayout,
    pristine: Option<&[u8]>,
) -> Restoration {
    let Ok(Some(directory)) = model.directory(restored, RESOURCE_DIRECTORY) else {
        return Restoration::Absent;
    };

    let root = directory.rva().as_usize();
    if root < end {
        return Restoration::Absent;
    }

    let Some(leaf) = lowest_moved_leaf(restored, model, end) else {
        return Restoration::Absent; // every resource stayed in the packer's section
    };

    let laid_out = sections
        .iter()
        .find(|section| section.contains(&leaf))
        .and_then(|section| {
            lay_out_resources(restored, model, root, section.clone(), layout, pristine)
        });
    match laid_out {
        Some(()) => Restoration::Restored,
        None => Restoration::Failed,
    }
}

pub(super) fn restore_tls(
    restored: &mut [u8],
    model: &PeModel,
    base: usize,
    end: usize,
    linker_place: Option<usize>,
) -> Restoration {
    let Ok(Some(copy)) = model.directory(restored, TLS_DIRECTORY) else {
        return Restoration::Absent;
    };

    let copy = copy.rva().as_usize();
    let length = match model.kind() {
        PeKind::Pe32 => TLS_DIRECTORY_PE32,
        PeKind::Pe32Plus => TLS_DIRECTORY_PE32_PLUS,
    };
    let refill = |restored: &mut [u8], place: usize| -> Option<usize> {
        (copy >= end && place < end).then_some(())?;
        let content = restored.get(copy..copy.checked_add(length)?)?.to_vec();
        self::place(restored, place, &content)?;
        Some(place)
    };
    let original = find_original_tls(restored, copy, model.kind(), end)
        .or_else(|| find_tls_by_template(restored, copy, model.kind(), base, end))
        .or_else(|| linker_place.and_then(|place| refill(restored, place)))
        .or_else(|| {
            let place = callbacks_in_directory(restored, copy, model.kind(), base)?;
            refill(restored, place)
        });
    match original.and_then(|rva| set_tls_directory(restored, model, rva)) {
        Some(()) => Restoration::Restored,
        None if tls_template(restored, copy, model.kind(), base, end).is_some() => {
            Restoration::Lost // the packer wiped the original, its copy still works
        }
        None => {
            clear_directory(restored, model, TLS_DIRECTORY);
            Restoration::Failed
        }
    }
}

pub(super) fn recover_directories(
    restored: &mut [u8],
    model: &PeModel,
    base: usize,
    end: usize,
    report: &mut PackerReport,
) {
    let lost = |restored: &[u8], index: usize| {
        model
            .directory(restored, index)
            .ok()
            .flatten()
            .is_none_or(|directory| directory.rva().as_usize() >= end)
    }; // gone, or at the packer's copy

    if lost(restored, LOAD_CONFIG_DIRECTORY)
        && let Some(rva) = find_load_config(restored, model.kind(), base, end)
        && set_directory(
            restored,
            model,
            LOAD_CONFIG_DIRECTORY,
            rva,
            LOAD_CONFIG_DIRECTORY_SIZE,
        )
        .is_some()
    {
        report.restored.push("load config");
    }

    if lost(restored, DELAY_IMPORT_DIRECTORY)
        && let Some((rva, size)) = find_delay_directory(restored, base, end)
        && set_directory(restored, model, DELAY_IMPORT_DIRECTORY, rva, size).is_some()
    {
        report.restored.push("delay imports");
    }

    if lost(restored, DEBUG_DIRECTORY)
        && let Some((rva, size)) = find_debug_directory(restored, end)
        && set_directory(restored, model, DEBUG_DIRECTORY, rva, size).is_some()
    {
        report.restored.push("debug directory");
    }
}

pub(super) fn security_cookie(bytes: &[u8], model: &PeModel, base: usize) -> Option<usize> {
    let directory = model.directory(bytes, LOAD_CONFIG_DIRECTORY).ok()??;
    let offset = match model.kind() {
        PeKind::Pe32 => LOAD_CONFIG_COOKIE_PE32,
        PeKind::Pe32Plus => LOAD_CONFIG_COOKIE_PE32_PLUS,
    };
    let at = directory.rva().as_usize().checked_add(offset)?;
    read_pointer(bytes, at, model.kind())
        .ok()?
        .checked_sub(base)
}

pub(super) fn debug_timestamp(bytes: &[u8], model: &PeModel) -> Option<u32> {
    let directory = model.directory(bytes, DEBUG_DIRECTORY).ok()??;
    let start = directory.rva().as_usize();
    (0..directory.size() as usize / DEBUG_ENTRY_SIZE)
        .filter_map(|index| {
            read_u32(
                bytes,
                start + index * DEBUG_ENTRY_SIZE + DEBUG_TIMESTAMP_OFFSET,
            )
            .ok()
        })
        .find(|timestamp| *timestamp != 0)
}

pub(super) struct PogoPart {
    pub(super) rva: usize,
    pub(super) size: usize,
    pub(super) name: Vec<u8>,
}

pub(super) fn pogo_parts(bytes: &[u8], model: &PeModel, end: usize) -> Option<Vec<PogoPart>> {
    let listed = model
        .directory(bytes, DEBUG_DIRECTORY)
        .ok()
        .flatten()
        .and_then(|directory| {
            let start = directory.rva().as_usize();
            (0..directory.size() as usize / DEBUG_ENTRY_SIZE).find_map(|index| {
                let entry = start.checked_add(index.checked_mul(DEBUG_ENTRY_SIZE)?)?;
                (read_u32(bytes, entry.checked_add(DEBUG_TYPE_OFFSET)?).ok()? == DEBUG_TYPE_POGO)
                    .then_some(())?;
                let rva = read_u32(bytes, entry.checked_add(DEBUG_ADDRESS_OFFSET)?).ok()? as usize;
                let size = read_u32(bytes, entry.checked_add(DEBUG_SIZE_OFFSET)?).ok()? as usize;
                Some(rva..rva.checked_add(size)?)
            })
        });
    let found = listed.or_else(|| {
        unique(
            (FIRST_SECTION_RVA..end)
                .step_by(SCAN_STEP)
                .filter(|at| {
                    pogo_data(bytes, *at, end)
                        && read_u32(bytes, at + POGO_RECORDS) == Ok(FIRST_SECTION_RVA as u32)
                })
                .map(|at| at..end),
        )
    })?; // a wiped debug directory leaves the data behind

    let mut parts: Vec<PogoPart> = Vec::new();
    let mut at = found.start.checked_add(POGO_RECORDS)?;
    while parts.len() < MAX_POGO_PARTS {
        let Some((part, next)) =
            pogo_record(bytes, at, found.end.min(bytes.len()), end, parts.last())
        else {
            break;
        };
        parts.push(part);
        at = next;
    }

    (parts.len() >= MIN_POGO_PARTS).then_some(parts)
}

fn pogo_record(
    bytes: &[u8],
    at: usize,
    records_end: usize,
    image_end: usize,
    previous: Option<&PogoPart>,
) -> Option<(PogoPart, usize)> {
    (at.checked_add(POGO_RECORD_HEADER)? < records_end).then_some(())?;
    let rva = read_u32(bytes, at).ok()? as usize;
    let size = read_u32(bytes, at.checked_add(4)?).ok()? as usize;
    let name_start = at.checked_add(POGO_RECORD_HEADER)?;
    let text = bytes.get(name_start..name_start.saturating_add(MAX_POGO_NAME).min(bytes.len()))?;
    let name = text.get(..text.iter().position(|byte| *byte == 0)?)?;
    let sound = (name.first() == Some(&b'.') || previous.is_some()) // later parts may be named like _RDATA
        && !name.is_empty()
        && name.iter().all(u8::is_ascii_graphic)
        && rva.checked_add(size).is_some_and(|stop| stop <= image_end)
        && previous.is_none_or(|last| last.rva <= rva);
    sound.then_some(())?;

    let next = name_start
        .checked_add(name.len() + 1)?
        .checked_next_multiple_of(4)?;
    let part = PogoPart {
        rva,
        size,
        name: name.to_vec(),
    };
    Some((part, next))
}

pub(super) fn pogo_sections(
    parts: &[PogoPart],
    model: &PeModel,
    end: usize,
    entry: Option<usize>,
) -> Option<Vec<SectionPiece>> {
    let alignment = model.section_alignment as usize;
    let first = model.sections().first()?.virtual_address().as_usize();
    let prefix = |name: &[u8]| -> Vec<u8> {
        name.split(|byte| *byte == b'$')
            .next()
            .unwrap_or(name)
            .to_vec()
    };
    let class = |prefix: &[u8]| -> Vec<u8> {
        match prefix {
            read_only if READ_ONLY_PARTS.contains(&read_only) => b".rdata".to_vec(),
            writable if WRITABLE_PARTS.contains(&writable) => b".data".to_vec(),
            other => other.to_vec(),
        }
    }; // a new class on a fresh page opens a section

    let mut sections: Vec<(usize, usize, Vec<Vec<u8>>)> = Vec::new(); // start, end of its parts, part names
    for part in parts.iter().filter(|part| part.rva < end) {
        let stop = part.rva.checked_add(part.size)?.min(end); // past the merged range the packer kept its own sections
        let name = prefix(&part.name);
        let opens = sections.last().is_none_or(|(_, last_end, names)| {
            let previous = names.last().map(|last| class(last));
            part.rva.is_multiple_of(alignment)
                && part.rva >= *last_end
                && (part.rva > *last_end || previous != Some(class(&name)))
        });
        match sections.last_mut() {
            Some((_, last_end, names)) if !opens => {
                *last_end = (*last_end).max(stop);
                names.push(name);
            }
            _ => sections.push((part.rva, stop, vec![name])),
        }
    }
    (sections.first().map(|(start, ..)| *start) == Some(first)).then_some(())?;

    let named = sections.iter().map(|(start, stop, names)| {
        let name = SECTION_NAMES
            .iter()
            .find(|wanted| names.iter().any(|name| name.as_slice() == **wanted))
            .map_or_else(
                || names.first().cloned().unwrap_or_default(),
                |name| name.to_vec(),
            );
        (*start, *stop, name)
    });
    let sections = named.collect::<Vec<_>>();

    let mut pieces = Vec::new();
    for (index, (start, _, name)) in sections.iter().enumerate() {
        let next = sections.get(index + 1).map_or(end, |(next, ..)| *next);
        let characteristics = match name.as_slice() {
            b".text" => CODE_SECTION,
            b".rdata" | b".pdata" => READ_ONLY_SECTION,
            b".rsrc" => RESOURCE_SECTION,
            _ => DATA_SECTION,
        };
        let mut padded = [0u8; 8];
        padded.get_mut(..name.len())?.copy_from_slice(name);
        pieces.push(SectionPiece {
            name: padded,
            start: *start,
            end: next,
            characteristics,
        });
    }

    let last = sections.last()?;
    let tail = last.1.checked_next_multiple_of(alignment)?; // the linker writes .reloc last and gives it no parts
    if tail < end {
        pieces.last_mut()?.end = tail;
        pieces.push(SectionPiece {
            name: *b".reloc\0\0",
            start: tail,
            end,
            characteristics: RELOCATION_SECTION,
        });
    }
    let runs_code = entry.is_none_or(|entry| {
        pieces.iter().any(|piece| {
            piece.characteristics == CODE_SECTION && (piece.start..piece.end).contains(&entry)
        })
    });
    runs_code.then_some(pieces)
}

pub(super) fn pogo_tls_directory(parts: &[PogoPart]) -> Option<usize> {
    unique(
        parts
            .iter()
            .filter(|part| part.name == TLS_PART)
            .map(|part| part.rva),
    )
}

fn pogo_data(bytes: &[u8], at: usize, end: usize) -> bool {
    let signature = bytes.get(at..at.saturating_add(POGO_RECORDS));
    let first = read_u32(bytes, at.saturating_add(POGO_RECORDS)).map(|rva| rva as usize);
    signature.is_some_and(|signature| POGO_SIGNATURES.contains(&signature))
        && first.is_ok_and(|rva| (FIRST_SECTION_RVA..end).contains(&rva))
        && bytes.get(at.saturating_add(POGO_FIRST_NAME)) == Some(&b'.')
}

pub(super) fn find_debug_directory(bytes: &[u8], end: usize) -> Option<(usize, usize)> {
    let record = bytes.get(..end).and_then(find_codeview_record);
    let field = |at: usize, offset: usize| {
        let entry = bytes.get(at..at.checked_add(DEBUG_ENTRY_SIZE)?)?;
        read_u32(entry, offset).ok()
    };
    let anchored = |at: usize| {
        let data = field(at, DEBUG_ADDRESS_OFFSET).map(|rva| rva as usize);
        let points_at_record = record
            .as_ref()
            .is_some_and(|record| data == Some(record.rva));
        field(at, 0) == Some(0)
            && data.is_some_and(|data| data < end)
            && match field(at, DEBUG_TYPE_OFFSET) {
                Some(DEBUG_TYPE_CODEVIEW) => points_at_record,
                Some(DEBUG_TYPE_POGO) => data.is_some_and(|data| pogo_data(bytes, data, end)),
                _ => false,
            }
    };
    let anchors = (FIRST_SECTION_RVA..end)
        .step_by(SCAN_STEP)
        .filter(|at| anchored(*at))
        .take(MAX_DEBUG_TYPE as usize + 1)
        .collect::<Vec<_>>();
    let codeview = *anchors.first()?;

    let timestamp = field(codeview, DEBUG_TIMESTAMP_OFFSET)?;
    let belongs = |at: usize| {
        field(at, 0) == Some(0)
            && field(at, DEBUG_TIMESTAMP_OFFSET) == Some(timestamp)
            && field(at, DEBUG_TYPE_OFFSET).is_some_and(|kind| (1..=MAX_DEBUG_TYPE).contains(&kind))
    };
    let mut start = codeview;
    while let Some(before) = start
        .checked_sub(DEBUG_ENTRY_SIZE)
        .filter(|at| belongs(*at))
    {
        start = before;
    }
    let mut stop = codeview.checked_add(DEBUG_ENTRY_SIZE)?;
    while belongs(stop) {
        stop = stop.checked_add(DEBUG_ENTRY_SIZE)?;
    }

    anchors
        .iter()
        .all(|anchor| (start..stop).contains(anchor))
        .then_some((start, stop - start))
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
    for (at, kind) in relocated_fields(restored, model)? {
        let Ok(value) = read_pointer(bytes, at, kind) else {
            continue;
        };
        let moved = adjust(value, kind);
        let _ = match kind {
            PeKind::Pe32 => write_u32(bytes, at, moved as u32),
            PeKind::Pe32Plus => write_u64(bytes, at, moved as u64),
        };
    }

    Some(())
}

pub(super) fn relocated_fields(restored: &[u8], model: &PeModel) -> Option<Vec<(usize, PeKind)>> {
    let directory = model.directory(restored, BASERELOC_DIRECTORY).ok()??;
    let start = directory.rva().as_usize();
    let table = restored.get(start..start.checked_add(directory.size() as usize)?)?;

    let mut fields = Vec::new();
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
            let kind = match word >> RELOCATION_KIND_SHIFT {
                RELOCATION_HIGHLOW => PeKind::Pe32,
                RELOCATION_DIR64 => PeKind::Pe32Plus,
                _ => continue,
            };
            fields.push((page + usize::from(word & RELOCATION_OFFSET_MASK), kind));
        }

        cursor += size;
    }

    Some(fields)
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

pub(super) fn find_delay_directory(
    bytes: &[u8],
    base: usize,
    end: usize,
) -> Option<(usize, usize)> {
    unique(
        (FIRST_SECTION_RVA..end)
            .step_by(SCAN_STEP)
            .filter(|at| {
                at.checked_sub(DELAY_DESCRIPTOR_SIZE)
                    .is_none_or(|before| !delay_descriptor(bytes, before, base, end))
            }) // every tail of a list is a valid list too
            .filter_map(|at| {
                let count = delay_descriptor_count(bytes, at, base, end)?;
                Some((
                    at,
                    count.checked_add(1)?.checked_mul(DELAY_DESCRIPTOR_SIZE)?,
                ))
            }),
    )
}

fn delay_descriptor_count(bytes: &[u8], start: usize, base: usize, end: usize) -> Option<usize> {
    for index in 0..MAX_DELAY_DESCRIPTORS {
        let at = start.checked_add(index.checked_mul(DELAY_DESCRIPTOR_SIZE)?)?;
        let descriptor = bytes.get(at..at.checked_add(DELAY_DESCRIPTOR_SIZE)?)?;

        if index > 0 && descriptor.iter().all(|byte| *byte == 0) {
            return Some(index);
        }
        if !delay_descriptor(bytes, at, base, end) {
            return None;
        }
    }

    None
}

fn delay_descriptor(bytes: &[u8], at: usize, base: usize, end: usize) -> bool {
    let in_image = |rva: usize| (FIRST_SECTION_RVA..end).contains(&rva);
    let Some(descriptor) = bytes.get(at..at.saturating_add(DELAY_DESCRIPTOR_SIZE)) else {
        return false;
    };

    let attributes = read_u32(descriptor, 0).ok();
    let rva_based = attributes == Some(DELAY_ATTRIBUTES_RVA_BASED);
    let address_based = attributes == Some(0);
    let field = |offset: usize| {
        let value = read_u32(descriptor, offset).ok()? as usize;
        match rva_based {
            true => Some(value),
            false => value.checked_sub(base),
        }
    };
    let handle = read_u32(descriptor, DELAY_HANDLE_OFFSET).ok();
    let loaded_module = handle.is_some_and(|handle| handle.is_multiple_of(MODULE_ALIGNMENT)); // delphi keeps the handle in the descriptor itself
    (rva_based || address_based)
        && (field(DELAY_HANDLE_OFFSET).is_some_and(in_image) || address_based && loaded_module)
        && field(DELAY_IAT_OFFSET).is_some_and(in_image)
        && field(DELAY_NAMES_OFFSET).is_some_and(in_image)
        && field(DELAY_NAME_OFFSET).is_some_and(|name| is_module_name(bytes, name))
}

fn is_module_name(bytes: &[u8], at: usize) -> bool {
    let Some(text) = bytes.get(at..at.saturating_add(MAX_DLL_NAME).min(bytes.len())) else {
        return false;
    };

    let Some(length) = text.iter().position(|byte| *byte == 0) else {
        return false;
    };

    let name = &text[..length];
    let extension = name.len().checked_sub(4).and_then(|dot| name.get(dot..));
    name.iter().all(u8::is_ascii_graphic)
        && extension.is_some_and(|extension| {
            extension[0] == b'.' && extension[1..].iter().all(u8::is_ascii_alphanumeric)
        }) // delphi delay loads winspool.drv
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

fn callbacks_in_directory(bytes: &[u8], copy: usize, kind: PeKind, base: usize) -> Option<usize> {
    let width = kind.pointer_width();
    let zero_fill = width.checked_mul(4)?;
    let callbacks = read_pointer(bytes, copy.checked_add(width * 3)?, kind).ok()?;
    (read_u32(bytes, copy.checked_add(zero_fill)?).ok()? == 0).then_some(())?;
    callbacks.checked_sub(base)?.checked_sub(zero_fill) // borland points the empty callback list at the directory's own zero fill
}

pub(super) fn find_tls_by_template(
    bytes: &[u8],
    copy: usize,
    kind: PeKind,
    base: usize,
    end: usize,
) -> Option<usize> {
    let template = |at: usize, limit: usize| tls_template(bytes, at, kind, base, limit);
    let (start, stop) = template(copy, bytes.len())?;
    let wanted = bytes.get(start..stop)?;
    unique((FIRST_SECTION_RVA..end).step_by(SCAN_STEP).filter(|at| {
        *at != copy
            && template(*at, end).is_some_and(|(other_start, other_stop)| {
                other_start != start && bytes.get(other_start..other_stop) == Some(wanted)
            })
    }))
}

fn tls_template(
    bytes: &[u8],
    at: usize,
    kind: PeKind,
    base: usize,
    limit: usize,
) -> Option<(usize, usize)> {
    let width = kind.pointer_width();
    let image = |pointer: usize| pointer.checked_sub(base).filter(|rva| *rva < limit);
    let start = image(read_pointer(bytes, at, kind).ok()?)?;
    let stop = image(read_pointer(bytes, at.checked_add(width)?, kind).ok()?)?;
    image(read_pointer(bytes, at.checked_add(width * 2)?, kind).ok()?)?;
    (stop > start).then_some((start, stop))
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
