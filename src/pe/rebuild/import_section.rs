use super::directories::{clear_directory, write_directory};
use super::{MAX_OUTPUT_SIZE, SECTION_HEADER_SIZE, align_up, align_up_u64};
use crate::pe::image::{read_u16, read_u32, write_u16, write_u32, write_u64};
use crate::pe::imports::{ImportGroup, ImportPlan};
use crate::pe::{IAT_DIRECTORY, IMPORT_DIRECTORY, PeKind, PeModel};
use crate::{AppError, AppResult};

const IMPORT_DESCRIPTOR_SIZE: usize = 20;
const MEMPE_IMPORT_CHARACTERISTICS: u32 = 0xC000_0040;

pub(super) enum ImportSection {
    Written { iat_cleared: bool },
    NothingToWrite,
    NoImportDirectory,
    NoRoomInHeaders,
}

pub(super) fn append_import_section(
    output: &mut Vec<u8>,
    model: &PeModel,
    plan: &ImportPlan,
) -> AppResult<ImportSection> {
    if IMPORT_DIRECTORY >= model.directory_count {
        return Ok(ImportSection::NoImportDirectory);
    }
    let section_header = model
        .sections
        .iter()
        .map(|section| section.header_offset)
        .max()
        .and_then(|offset| offset.checked_add(SECTION_HEADER_SIZE))
        .ok_or_else(|| AppError::new("new section-header offset overflowed"))?;
    let header_limit = usize::try_from(read_u32(output, model.size_of_headers_offset)?)
        .map_err(|_| AppError::new("PE header size does not fit memory"))?;
    if section_header.saturating_add(SECTION_HEADER_SIZE) > header_limit {
        return Ok(ImportSection::NoRoomInHeaders);
    }
    let virtual_address = align_up_u64(
        u64::from(read_u32(output, model.size_of_image_offset)?),
        u64::from(model.section_alignment),
    )?;
    let virtual_address = u32::try_from(virtual_address)
        .map_err(|_| AppError::new("import section RVA exceeds u32"))?;
    let payload = build_import_payload(plan, model.kind, virtual_address)?;
    let raw_offset = align_up(output.len(), model.file_alignment as usize)?;
    let raw_size = align_up(payload.len(), model.file_alignment as usize)?;
    let final_size = raw_offset
        .checked_add(raw_size)
        .ok_or_else(|| AppError::new("import section output size overflowed"))?;
    if final_size > MAX_OUTPUT_SIZE {
        return Err(AppError::new(
            "recovered imports exceed the 1 GiB output safety limit",
        ));
    }
    output.resize(final_size, 0);
    let payload_end = raw_offset
        .checked_add(payload.len())
        .ok_or_else(|| AppError::new("import payload range overflowed"))?;
    output
        .get_mut(raw_offset..payload_end)
        .ok_or_else(|| AppError::new("import payload lies outside the rebuilt PE"))?
        .copy_from_slice(&payload);

    write_mempe_section_header(
        output,
        section_header,
        virtual_address,
        payload.len(),
        raw_offset,
        raw_size,
    )?;
    let iat_cleared = commit_import_section(output, model, plan, virtual_address, payload.len())?;
    Ok(ImportSection::Written { iat_cleared })
}

fn write_mempe_section_header(
    output: &mut [u8],
    section_header: usize,
    virtual_address: u32,
    virtual_size: usize,
    raw_offset: usize,
    raw_size: usize,
) -> AppResult<()> {
    let name = output
        .get_mut(section_header..section_header.saturating_add(8))
        .ok_or_else(|| AppError::new("new section name lies outside the PE headers"))?;
    name.copy_from_slice(b".mempe\0\0");
    write_u32(
        output,
        section_header.saturating_add(8),
        u32::try_from(virtual_size)
            .map_err(|_| AppError::new("import payload size exceeds u32"))?,
    )?;
    write_u32(output, section_header.saturating_add(12), virtual_address)?;
    write_u32(
        output,
        section_header.saturating_add(16),
        u32::try_from(raw_size).map_err(|_| AppError::new("import raw size exceeds u32"))?,
    )?;
    write_u32(
        output,
        section_header.saturating_add(20),
        u32::try_from(raw_offset).map_err(|_| AppError::new("import file offset exceeds u32"))?,
    )?;
    write_u32(
        output,
        section_header.saturating_add(36),
        MEMPE_IMPORT_CHARACTERISTICS,
    )
}

fn commit_import_section(
    output: &mut [u8],
    model: &PeModel,
    plan: &ImportPlan,
    virtual_address: u32,
    payload_len: usize,
) -> AppResult<bool> {
    let section_count_offset = model.nt_offset.saturating_add(6);
    let section_count = read_u16(output, section_count_offset)?
        .checked_add(1)
        .ok_or_else(|| AppError::new("section count overflowed"))?;
    write_u16(output, section_count_offset, section_count)?;
    let image_end = u64::from(virtual_address)
        .checked_add(payload_len as u64)
        .ok_or_else(|| AppError::new("import virtual range overflowed"))?;
    let image_size = align_up_u64(image_end, u64::from(model.section_alignment))?;
    write_u32(
        output,
        model.size_of_image_offset,
        u32::try_from(image_size).map_err(|_| AppError::new("image size exceeds u32"))?,
    )?;
    let descriptor_size = u32::try_from(import_descriptor_bytes(plan)?)
        .map_err(|_| AppError::new("import descriptor size exceeds u32"))?;
    write_directory(
        output,
        model,
        IMPORT_DIRECTORY,
        virtual_address,
        descriptor_size,
    )?;
    if plan.existing.is_empty() {
        return Ok(clear_directory(output, model, IAT_DIRECTORY)? > 0);
    }
    Ok(false)
}

fn build_import_payload(plan: &ImportPlan, kind: PeKind, section_rva: u32) -> AppResult<Vec<u8>> {
    let width = kind.pointer_width();
    let mut payload = plan.existing.clone();
    payload.resize(import_descriptor_bytes(plan)?, 0);
    for (group_index, group) in plan.groups.iter().enumerate() {
        align_vec(&mut payload, width);
        let lookup_offset = payload.len();
        let lookup_size = group
            .entries
            .len()
            .checked_add(1)
            .and_then(|count| count.checked_mul(width))
            .ok_or_else(|| AppError::new("import lookup-table size overflowed"))?;
        payload.resize(payload.len().saturating_add(lookup_size), 0);
        write_lookup_thunks(&mut payload, group, kind, section_rva, lookup_offset)?;
        let module_offset = payload.len();
        append_ascii(&mut payload, &group.module)?;
        let descriptor = group_index
            .checked_mul(IMPORT_DESCRIPTOR_SIZE)
            .and_then(|offset| offset.checked_add(plan.existing.len()))
            .ok_or_else(|| AppError::new("import descriptor offset overflowed"))?;
        write_import_descriptor(
            &mut payload,
            descriptor,
            section_rva,
            lookup_offset,
            module_offset,
            group.first_thunk,
        )?;
    }
    Ok(payload)
}

fn write_lookup_thunks(
    payload: &mut Vec<u8>,
    group: &ImportGroup,
    kind: PeKind,
    section_rva: u32,
    lookup_offset: usize,
) -> AppResult<()> {
    let width = kind.pointer_width();
    for (entry_index, entry) in group.entries.iter().enumerate() {
        let thunk = match &entry.name {
            Some(name) => {
                align_vec(payload, 2);
                let name_offset = payload.len();
                payload.extend_from_slice(&[0, 0]);
                append_ascii(payload, name)?;
                u64::from(section_rva)
                    .checked_add(name_offset as u64)
                    .ok_or_else(|| AppError::new("import name RVA overflowed"))?
            }
            None => ordinal_thunk(kind, entry.ordinal),
        };
        let thunk_offset = lookup_offset
            .checked_add(entry_index.saturating_mul(width))
            .ok_or_else(|| AppError::new("import thunk offset overflowed"))?;
        write_thunk(payload, thunk_offset, kind, thunk)?;
    }
    Ok(())
}

fn ordinal_thunk(kind: PeKind, ordinal: u32) -> u64 {
    let flag = if kind == PeKind::Pe32 {
        0x8000_0000u64
    } else {
        0x8000_0000_0000_0000u64
    };
    flag | u64::from(ordinal & 0xffff)
}

fn write_import_descriptor(
    payload: &mut [u8],
    descriptor: usize,
    section_rva: u32,
    lookup_offset: usize,
    module_offset: usize,
    first_thunk: u32,
) -> AppResult<()> {
    write_u32(
        payload,
        descriptor,
        payload_rva(section_rva, lookup_offset, "import lookup-table")?,
    )?;
    write_u32(
        payload,
        descriptor.saturating_add(12),
        payload_rva(section_rva, module_offset, "import module")?,
    )?;
    write_u32(payload, descriptor.saturating_add(16), first_thunk)
}

fn payload_rva(section_rva: u32, offset: usize, what: &str) -> AppResult<u32> {
    let offset =
        u32::try_from(offset).map_err(|_| AppError::new(format!("{what} offset exceeds u32")))?;
    section_rva
        .checked_add(offset)
        .ok_or_else(|| AppError::new(format!("{what} RVA overflowed")))
}

fn import_descriptor_bytes(plan: &ImportPlan) -> AppResult<usize> {
    plan.groups
        .len()
        .checked_add(1)
        .and_then(|count| count.checked_mul(IMPORT_DESCRIPTOR_SIZE))
        .and_then(|size| size.checked_add(plan.existing.len()))
        .ok_or_else(|| AppError::new("import descriptor size overflowed"))
}

fn append_ascii(bytes: &mut Vec<u8>, value: &str) -> AppResult<()> {
    if value.is_empty() || !value.is_ascii() || value.as_bytes().contains(&0) {
        return Err(AppError::new("import name is not valid ASCII"));
    }
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(0);
    Ok(())
}

fn align_vec(bytes: &mut Vec<u8>, alignment: usize) {
    bytes.resize(bytes.len().next_multiple_of(alignment), 0);
}

fn write_thunk(bytes: &mut [u8], offset: usize, kind: PeKind, value: u64) -> AppResult<()> {
    match kind {
        PeKind::Pe32 => write_u32(
            bytes,
            offset,
            u32::try_from(value).map_err(|_| AppError::new("PE32 import thunk exceeds u32"))?,
        ),
        PeKind::Pe32Plus => write_u64(bytes, offset, value),
    }
}
