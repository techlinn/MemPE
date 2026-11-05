use super::read_c_string;
use super::resources::MAX_RESOURCE_ENTRIES;
use crate::pe::image::{read_u16, read_u32, write_u32};

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

pub(crate) fn exports_intact(bytes: &[u8], start: usize) -> bool {
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

pub(crate) fn export_functions(bytes: &[u8], start: usize) -> Option<Vec<usize>> {
    let count = read_u32(bytes, start.checked_add(EXPORT_FUNCTION_COUNT_OFFSET)?).ok()? as usize;
    let table = read_u32(bytes, start.checked_add(EXPORT_FUNCTIONS_OFFSET)?).ok()? as usize;
    (0..count.min(MAX_RESOURCE_ENTRIES))
        .map(|index| {
            let at = table.checked_add(index.checked_mul(EXPORT_TABLE_ENTRY_SIZE)?)?;
            Some(read_u32(bytes, at).ok()? as usize)
        })
        .collect()
}

pub(crate) fn linker_export_layout(
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

pub(crate) fn linker_export_start(bytes: &[u8], copy: usize) -> Option<usize> {
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

pub(crate) fn moved_export_directory(
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
