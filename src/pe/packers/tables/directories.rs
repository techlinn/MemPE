use super::debug::find_debug_directory;
use super::{FIRST_SECTION_RVA, SCAN_STEP, set_directory, unique};
use crate::pe::image::{read_pointer, read_u32};
use crate::pe::packers::PackerReport;
use crate::pe::{DEBUG_DIRECTORY, DELAY_IMPORT_DIRECTORY, LOAD_CONFIG_DIRECTORY, PeKind, PeModel};

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
const MODULE_ALIGNMENT: u32 = 0x1_0000;

pub(crate) fn recover_directories(
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

pub(crate) fn security_cookie(bytes: &[u8], model: &PeModel, base: usize) -> Option<usize> {
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

fn find_delay_directory(bytes: &[u8], base: usize, end: usize) -> Option<(usize, usize)> {
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

fn find_load_config(bytes: &[u8], kind: PeKind, base: usize, end: usize) -> Option<usize> {
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
