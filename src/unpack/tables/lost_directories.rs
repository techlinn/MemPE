use std::ops::Range;

use super::debug_directory::find_debug_directory;
use super::{SCAN_STEP, Search, sole, unique};
use crate::pe::bytes::{read_pointer, read_u32, write_u32};
use crate::pe::{
    DEBUG_DIRECTORY, DELAY_ATTRIBUTES_RVA_BASED, DELAY_DESCRIPTOR_SIZE, DELAY_HANDLE_OFFSET,
    DELAY_IAT_OFFSET, DELAY_IMPORT_DIRECTORY, DELAY_INT_OFFSET, DELAY_NAME_OFFSET,
    LOAD_CONFIG_DIRECTORY, LOAD_CONFIG_HANDLERS_PE32, MAX_SAFESEH_HANDLERS, MODULE_ALIGNMENT,
    PeKind, PeModel, Rva, SAFESEH_HANDLER_SIZE, first_section_rva,
};
use crate::unpack::{PackerReport, Part};

const MAX_DELAY_DESCRIPTORS: usize = 256;
const MAX_DLL_NAME: usize = 256;
const LOAD_CONFIG_TIMESTAMP_OFFSET: usize = 4;
const LOAD_CONFIG_COOKIE_PE32: usize = 0x3C;
const LOAD_CONFIG_COOKIE_PE32_PLUS: usize = 0x58;
const LOAD_CONFIG_HANDLERS_PE32_PLUS: usize = 0x60;
const LOAD_CONFIG_HANDLERS_END_PE32_PLUS: usize = 0x70;
const LOAD_CONFIG_VERSION_OFFSET: usize = 8; // linkers leave it zero
const LOAD_FLAGS_SIZE: usize = 2;
pub(super) const MAX_LOAD_CONFIG_SIZE: u32 = 0x400;
const LOAD_CONFIG_DIRECTORY_SIZE: usize = 0x40; // msvc PE32 value
const LOAD_CONFIG_THROUGH_HANDLERS: u32 = 0x48; // the size is gone, this much is known to be there
const COOKIE_COMPLEMENT_DISTANCES: [usize; 2] = [4, 0x40]; // older crts, then the cache line aligned pair
const MIN_COOKIE_READS: usize = 2;
const RANDOM_BITS: std::ops::RangeInclusive<u32> = 4..=28; // a cookie is random, 1 and its complement are not
pub(super) const FOUND_BY_SEARCH: &str = "found by search";
const SEVERAL_CANDIDATES: &str = "more than one place looks like it";
const COOKIE_ESTIMATED: &str = "found by search, its size and cookie pointer are estimates";
const COOKIE_GONE: &str = "found by search, its size is an estimate and its cookie pointer is gone";

struct LoadConfigScan<'a> {
    kind: PeKind,
    base: usize,
    linked_base: usize,
    image: Range<usize>,
    writable: &'a [Range<usize>],
}

pub(crate) fn recover_directories(
    restored: &mut [u8],
    model: &PeModel,
    base: usize,
    end: usize,
    writable: &[Range<usize>],
    report: &mut PackerReport,
) {
    let Some(first) = first_section_rva(&model.sections) else {
        return;
    };

    if lost(restored, model, LOAD_CONFIG_DIRECTORY, end) {
        let scan = LoadConfigScan {
            kind: model.kind,
            base,
            linked_base: base,
            image: first..end,
            writable,
        };
        let found = find_load_config(restored, &scan)
            .filter_map(|rva| Some((rva, load_config_directory_size(restored, model.kind, rva)?)));
        declare(restored, model, LOAD_CONFIG_DIRECTORY, found, report);
    }

    if lost(restored, model, DELAY_IMPORT_DIRECTORY, end) {
        let found = find_delay_directory(restored, base, &(first..end));
        declare(restored, model, DELAY_IMPORT_DIRECTORY, found, report);
    }

    if lost(restored, model, DEBUG_DIRECTORY, end) {
        let found = find_debug_directory(restored, &(first..end));
        declare(restored, model, DEBUG_DIRECTORY, found, report);
    }
}

fn lost(restored: &[u8], model: &PeModel, index: usize, end: usize) -> bool {
    model
        .directory(restored, index)
        .is_none_or(|directory| directory.rva().as_usize() >= end)
}

fn declare(
    restored: &mut [u8],
    model: &PeModel,
    index: usize,
    found: Search<(usize, usize)>,
    report: &mut PackerReport,
) {
    let part = match index {
        LOAD_CONFIG_DIRECTORY => Part::LoadConfig,
        DELAY_IMPORT_DIRECTORY => Part::DelayImports,
        _ => Part::DebugDirectory,
    };

    match found {
        Search::One((rva, size)) => match model.set_directory(restored, index, rva, size) {
            Some(()) => report.inferred(part, FOUND_BY_SEARCH),
            None => report.failed(part),
        },
        Search::Several => report.failed_with(part, SEVERAL_CANDIDATES),
        Search::None => {}
    }
}

fn rebase_handler_table(
    restored: &mut [u8],
    rva: usize,
    base: usize,
    linked_base: usize,
    end: usize,
) {
    let handlers = rva + LOAD_CONFIG_HANDLERS_PE32;
    let stale = read_u32(restored, handlers)
        .ok()
        .and_then(|table| (table as usize).checked_sub(linked_base))
        .filter(|table| base != linked_base && *table < end)
        .and_then(|table| u32::try_from(base + table).ok());
    if let Some(table) = stale {
        let _ = write_u32(restored, handlers, table); // its relocation was stripped with the directory
    }
}

pub(crate) fn restore_load_config(
    restored: &mut [u8],
    model: &PeModel,
    base: usize,
    linked_base: usize,
    end: usize,
    writable: &[Range<usize>],
    report: &mut PackerReport,
) {
    if !lost(restored, model, LOAD_CONFIG_DIRECTORY, end) || model.kind != PeKind::Pe32 {
        return;
    }
    let Some(first) = first_section_rva(&model.sections) else {
        return;
    };

    let scan = LoadConfigScan {
        kind: model.kind,
        base,
        linked_base,
        image: first..end,
        writable,
    };
    let found = find_load_config(restored, &scan);
    if let Search::One(rva) = found {
        rebase_handler_table(restored, rva, base, linked_base, end);
    }
    if !matches!(found, Search::None) {
        let found = found.filter_map(|rva| Some((rva, LOAD_CONFIG_DIRECTORY_SIZE)));
        return declare(restored, model, LOAD_CONFIG_DIRECTORY, found, report);
    }

    let executable =
        |rva: usize| u32::try_from(rva).is_ok_and(|rva| model.executable_rva(Rva(rva)));
    let rva =
        match find_wiped_load_config(restored, [base, linked_base], &(first..end), &executable) {
            Search::One(rva) => rva,
            Search::Several => return report.failed_with(Part::LoadConfig, SEVERAL_CANDIDATES),
            Search::None => return,
        };

    let cookie = find_security_cookie(restored, base, &(first..end))
        .and_then(|cookie| u32::try_from(base.checked_add(cookie)?).ok());
    rebase_handler_table(restored, rva, base, linked_base, end);
    let size = LOAD_CONFIG_DIRECTORY_SIZE;
    let written = model
        .set_directory(restored, LOAD_CONFIG_DIRECTORY, rva, size)
        .and_then(|()| write_u32(restored, rva, LOAD_CONFIG_THROUGH_HANDLERS).ok())
        .and_then(|()| {
            write_u32(restored, rva + LOAD_CONFIG_COOKIE_PE32, cookie.unwrap_or(0)).ok()
        });

    match (written, cookie) {
        (None, _) => report.failed(Part::LoadConfig),
        (Some(()), Some(_)) => report.inferred(Part::LoadConfig, COOKIE_ESTIMATED),
        (Some(()), None) => report.inferred(Part::LoadConfig, COOKIE_GONE),
    }
}

pub(crate) fn safe_handlers(bytes: &[u8], table: usize, count: u32) -> Option<Vec<u32>> {
    (0..count as usize)
        .map(|index| read_u32(bytes, table.checked_add(index * SAFESEH_HANDLER_SIZE)?).ok())
        .collect()
}

fn handlers_in_order(bytes: &[u8], table: usize, count: u32, image: &Range<usize>) -> bool {
    if !table.is_multiple_of(SAFESEH_HANDLER_SIZE) || count > MAX_SAFESEH_HANDLERS {
        return false;
    }

    safe_handlers(bytes, table, count).is_some_and(|handlers| {
        handlers.is_sorted_by(|left, right| left < right)
            && handlers
                .iter()
                .all(|handler| image.contains(&(*handler as usize)))
    })
}

// its relocation goes with the directory, so the table may still hold the linked address
fn find_wiped_load_config(
    bytes: &[u8],
    bases: [usize; 2],
    image: &Range<usize>,
    code: &dyn Fn(usize) -> bool,
) -> Search<usize> {
    let rva_of = |address: u32| {
        bases.into_iter().find_map(|base| {
            (address as usize)
                .checked_sub(base)
                .filter(|rva| image.contains(rva))
        })
    };

    sole(image.clone().step_by(SCAN_STEP).filter(|at| {
        let wiped = bytes
            .get(*at..at.saturating_add(LOAD_CONFIG_COOKIE_PE32))
            .is_some_and(|head| head.iter().all(|byte| *byte == 0))
            && read_u32(bytes, at + LOAD_CONFIG_COOKIE_PE32)
                .is_ok_and(|cookie| cookie.is_multiple_of(MODULE_ALIGNMENT)); // zero, plus the loader's fixup
        let table = read_u32(bytes, at + LOAD_CONFIG_HANDLERS_PE32).ok();
        let count = read_u32(bytes, at + LOAD_CONFIG_HANDLERS_PE32 + 4).unwrap_or(0);
        if !wiped || count == 0 {
            return false;
        }

        table.and_then(rva_of).is_some_and(|table| {
            handlers_in_order(bytes, table, count, image)
                && safe_handlers(bytes, table, count).is_some_and(|handlers| {
                    handlers.iter().all(|handler| code(*handler as usize)) // handlers are code
                })
        })
    }))
}

fn find_security_cookie(bytes: &[u8], base: usize, image: &Range<usize>) -> Option<usize> {
    let mapped = bytes.get(..image.end)?;
    let reads = |rva: usize| {
        let Some(address) = base
            .checked_add(rva)
            .and_then(|address| u32::try_from(address).ok())
        else {
            return 0;
        };

        let address = address.to_le_bytes();
        mapped
            .windows(4)
            .filter(|window| *window == address)
            .count()
    };

    let pairs = image.clone().step_by(SCAN_STEP).filter_map(|at| {
        let value = read_u32(bytes, at)
            .ok()
            .filter(|value| RANDOM_BITS.contains(&value.count_ones()))?;
        let twin = COOKIE_COMPLEMENT_DISTANCES
            .into_iter()
            .map(|distance| at + distance)
            .find(|twin| read_u32(bytes, *twin) == Ok(!value))?;

        let (here, there) = (reads(at), reads(twin));
        match here.max(there) >= MIN_COOKIE_READS && here != there {
            true => Some(if here > there { at } else { twin }), // every guarded function reads the cookie, one reads its complement
            false => None,
        }
    });
    unique(pairs)
}

pub(crate) fn safeseh_field(bytes: &[u8], model: &PeModel) -> Option<usize> {
    let directory = model.directory(bytes, LOAD_CONFIG_DIRECTORY)?;
    (model.kind == PeKind::Pe32).then_some(())?;

    let rva = directory.rva().as_usize();
    let size = read_u32(bytes, rva).ok()?;
    (size >= LOAD_CONFIG_THROUGH_HANDLERS).then_some(())?; // older structs end before the table

    rva.checked_add(LOAD_CONFIG_HANDLERS_PE32)
}

pub(crate) fn security_cookie(bytes: &[u8], model: &PeModel, base: usize) -> Option<usize> {
    let directory = model.directory(bytes, LOAD_CONFIG_DIRECTORY)?;
    let offset = match model.kind {
        PeKind::Pe32 => LOAD_CONFIG_COOKIE_PE32,
        PeKind::Pe32Plus => LOAD_CONFIG_COOKIE_PE32_PLUS,
    };

    let rva = directory.rva().as_usize();
    let size = read_u32(bytes, rva).ok()? as usize;
    (size >= offset.checked_add(model.kind.pointer_width())?).then_some(())?;

    let at = rva.checked_add(offset)?;
    read_pointer(bytes, at, model.kind).ok()?.checked_sub(base)
}

fn find_delay_directory(bytes: &[u8], base: usize, image: &Range<usize>) -> Search<(usize, usize)> {
    sole(
        image
            .clone()
            .step_by(SCAN_STEP)
            .filter(|at| {
                at.checked_sub(DELAY_DESCRIPTOR_SIZE)
                    .is_none_or(|before| !delay_descriptor(bytes, before, base, image))
            })
            .filter_map(|at| {
                let count = delay_descriptor_count(bytes, at, base, image)?;
                Some((
                    at,
                    count.checked_add(1)?.checked_mul(DELAY_DESCRIPTOR_SIZE)?,
                ))
            }),
    )
}

fn delay_descriptor_count(
    bytes: &[u8],
    start: usize,
    base: usize,
    image: &Range<usize>,
) -> Option<usize> {
    for index in 0..MAX_DELAY_DESCRIPTORS {
        let at = start.checked_add(index.checked_mul(DELAY_DESCRIPTOR_SIZE)?)?;
        let descriptor = bytes.get(at..at.checked_add(DELAY_DESCRIPTOR_SIZE)?)?;

        if index > 0 && descriptor.iter().all(|byte| *byte == 0) {
            return Some(index);
        }
        if !delay_descriptor(bytes, at, base, image) {
            return None;
        }
    }

    None
}

fn delay_descriptor(bytes: &[u8], at: usize, base: usize, image: &Range<usize>) -> bool {
    let in_image = |rva: usize| image.contains(&rva);
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
    let loaded_module = handle.is_some_and(|handle| handle.is_multiple_of(MODULE_ALIGNMENT)); // delphi keeps the handle in the descriptor

    (rva_based || address_based)
        && (field(DELAY_HANDLE_OFFSET).is_some_and(in_image) || address_based && loaded_module)
        && field(DELAY_IAT_OFFSET).is_some_and(in_image)
        && field(DELAY_INT_OFFSET).is_some_and(in_image)
        && field(DELAY_NAME_OFFSET).is_some_and(|name| is_module_name(bytes, name))
}

pub(crate) fn is_module_name(bytes: &[u8], at: usize) -> bool {
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

fn find_load_config(bytes: &[u8], scan: &LoadConfigScan<'_>) -> Search<usize> {
    let kind = scan.kind;
    let width = kind.pointer_width();
    let (cookie_offset, read_through) = match kind {
        PeKind::Pe32 => (
            LOAD_CONFIG_COOKIE_PE32,
            LOAD_CONFIG_THROUGH_HANDLERS as usize,
        ),
        PeKind::Pe32Plus => (
            LOAD_CONFIG_COOKIE_PE32_PLUS,
            LOAD_CONFIG_COOKIE_PE32_PLUS + width,
        ),
    };

    sole(scan.image.clone().step_by(SCAN_STEP).filter(|at| {
        let size = read_u32(bytes, *at).unwrap_or(0);
        let cookie = read_pointer(bytes, at.saturating_add(cookie_offset), kind).ok();
        let cookie_rva = cookie
            .and_then(|cookie| cookie.checked_sub(scan.base))
            .filter(|rva| scan.image.contains(rva));

        size as usize > cookie_offset.saturating_add(width)
            && size as usize >= read_through
            && size <= MAX_LOAD_CONFIG_SIZE
            && size.is_multiple_of(4)
            && read_u32(bytes, at.saturating_add(LOAD_CONFIG_TIMESTAMP_OFFSET)) == Ok(0)
            && tuning_fields_unset(bytes, *at, cookie_offset, width)
            && cookie_rva.is_some_and(|rva| {
                rva.is_multiple_of(width) && scan.writable.iter().any(|range| range.contains(&rva)) // the crt writes it
            })
            && match kind {
                PeKind::Pe32 => safeseh_fits(bytes, *at, scan),
                PeKind::Pe32Plus => x64_fields_fit(bytes, *at, size as usize, cookie, scan.base),
            }
    }))
}

// only a hand written config sets the heap and timeout knobs; DependentLoadFlags comes from a linker switch
fn tuning_fields_unset(bytes: &[u8], at: usize, cookie_offset: usize, width: usize) -> bool {
    let edit_list = cookie_offset - width;
    let dependent_load_flags = edit_list - LOAD_FLAGS_SIZE;
    let zero = |range: Range<usize>| {
        bytes
            .get(at.saturating_add(range.start)..at.saturating_add(range.end))
            .is_some_and(|fields| fields.iter().all(|byte| *byte == 0))
    };

    zero(LOAD_CONFIG_TIMESTAMP_OFFSET..dependent_load_flags) && zero(edit_list..cookie_offset)
}

pub(crate) fn load_config_length(bytes: &[u8], rva: usize, declared: usize) -> usize {
    let own = read_u32(bytes, rva).map_or(0, |size| size.min(MAX_LOAD_CONFIG_SIZE));
    declared.max(own as usize) // PE32 says 0x40 whatever the struct
}

fn load_config_directory_size(bytes: &[u8], kind: PeKind, rva: usize) -> Option<usize> {
    match kind {
        PeKind::Pe32 => Some(LOAD_CONFIG_DIRECTORY_SIZE),
        PeKind::Pe32Plus => read_u32(bytes, rva).ok().map(|size| size as usize),
    }
}

fn x64_fields_fit(
    bytes: &[u8],
    at: usize,
    size: usize,
    cookie: Option<usize>,
    base: usize,
) -> bool {
    let pointer = |offset: usize| read_pointer(bytes, at.saturating_add(offset), PeKind::Pe32Plus);
    let no_handlers = size < LOAD_CONFIG_HANDLERS_END_PE32_PLUS
        || (pointer(LOAD_CONFIG_HANDLERS_PE32_PLUS) == Ok(0)
            && pointer(LOAD_CONFIG_HANDLERS_PE32_PLUS + 8) == Ok(0)); // no safeseh on x64
    let seeded = cookie
        .filter(|cookie| cookie.is_multiple_of(8))
        .and_then(|cookie| cookie.checked_sub(base))
        .is_some_and(|rva| {
            read_pointer(bytes, rva, PeKind::Pe32Plus).is_ok_and(|value| value != 0)
        });

    read_u32(bytes, at.saturating_add(LOAD_CONFIG_VERSION_OFFSET)) == Ok(0) && no_handlers && seeded
}

fn safeseh_fits(bytes: &[u8], at: usize, scan: &LoadConfigScan<'_>) -> bool {
    let field = |offset: usize| read_u32(bytes, at.saturating_add(offset)).ok();
    let (Some(table), Some(count)) = (
        field(LOAD_CONFIG_HANDLERS_PE32),
        field(LOAD_CONFIG_HANDLERS_PE32 + 4),
    ) else {
        return false;
    };
    if table == 0 || count == 0 {
        return table == 0 && count == 0; // a table and its count come together
    }

    let table = table as usize;
    let rva_from = |base: usize| {
        table
            .checked_sub(base)
            .filter(|rva| scan.image.contains(rva))
    };
    rva_from(scan.base)
        .or_else(|| rva_from(scan.linked_base))
        .is_some_and(|table| handlers_in_order(bytes, table, count, &scan.image)) // the loader searches it by halving
}
