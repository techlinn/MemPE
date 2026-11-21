use std::ops::Range;

use super::{
    IMAGE_SCN_CNT_INITIALIZED_DATA, MAX_OUTPUT_SIZE, SECTION_HEADER_SIZE, align_up, align_up_u64,
    output_too_large,
};
use crate::import_recovery::{ImportGroup, ImportPlan};
use crate::pe::bytes::{read_pointer, read_u16, read_u32, write_pointer, write_u16, write_u32};
use crate::pe::{BOUND_IMPORT_DIRECTORY, IAT_DIRECTORY, IMPORT_DIRECTORY, PeKind, PeModel};
use crate::pe::{IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE};
use crate::pe::{IMPORT_DESCRIPTOR_SIZE, IMPORT_IAT_OFFSET, IMPORT_NAME_OFFSET, SECTION_NAME_SIZE};
use crate::pe::{
    SECTION_CHARACTERISTICS_OFFSET, SECTION_COUNT_OFFSET, SECTION_RAW_POINTER_OFFSET,
    SECTION_RAW_SIZE_OFFSET, SECTION_RVA_OFFSET, SECTION_VIRTUAL_SIZE_OFFSET,
};
use crate::{AppError, AppResult};

const MEMPE_IMPORT_CHARACTERISTICS: u32 =
    IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA;

// None: no room in the headers; Some: the directories it cleared
pub(super) fn append_import_section(
    output: &mut Vec<u8>,
    model: &PeModel,
    plan: &ImportPlan,
    slot_offset: impl Fn(u32) -> Option<usize>,
) -> AppResult<Option<Vec<usize>>> {
    if IMPORT_DIRECTORY >= model.directory_count {
        return Ok(None);
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
    let section_count = read_u16(output, model.nt_offset.saturating_add(SECTION_COUNT_OFFSET))?;
    let slot = section_header..section_header.saturating_add(SECTION_HEADER_SIZE);

    if section_count == u16::MAX || slot.end > header_limit {
        return Ok(None);
    }

    // the loader reads only the declared headers: bytes past them that nothing points at are free,
    // a removed section's header included
    if model.header_bytes_in_use(output, &slot, Some(BOUND_IMPORT_DIRECTORY)) {
        return Ok(None);
    }

    let bound_table = bound_table_in_slack(output, model, section_header, header_limit)?;

    let virtual_address = align_up_u64(
        u64::from(read_u32(output, model.size_of_image_offset)?),
        u64::from(model.section_alignment),
    )?;
    let virtual_address = u32::try_from(virtual_address)
        .map_err(|_| AppError::new("import section RVA exceeds u32"))?;
    let payload = build_import_payload(plan, model.kind, virtual_address)?;

    let raw_offset = match model.is_low_alignment() {
        true => virtual_address as usize, // low alignment: offset == rva
        false => align_up(output.len(), model.file_alignment as usize)?,
    };

    if raw_offset < output.len() {
        return Err(AppError::new(
            "the import section would overwrite section data in this low-alignment image",
        ));
    }

    let raw_size = align_up(payload.len(), model.file_alignment as usize)?;
    let final_size = raw_offset
        .checked_add(raw_size)
        .ok_or_else(|| AppError::new("import section output size overflowed"))?;

    if final_size > MAX_OUTPUT_SIZE {
        return Err(output_too_large(
            "the rebuilt PE with its import section",
            final_size,
        ));
    }

    let bound_cleared = clear_bound_imports(output, model, bound_table, &slot)?;
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

    fill_empty_slots(
        output,
        plan,
        &payload,
        model.kind,
        virtual_address,
        slot_offset,
    )?;

    let mut cleared = Vec::new();

    if bound_cleared {
        cleared.push(BOUND_IMPORT_DIRECTORY);
    }

    if commit_import_section(output, model, plan, virtual_address, payload.len())? {
        cleared.push(IAT_DIRECTORY);
    }

    Ok(Some(cleared))
}

fn fill_empty_slots(
    output: &mut [u8],
    plan: &ImportPlan,
    payload: &[u8],
    kind: PeKind,
    section_rva: u32,
    slot_offset: impl Fn(u32) -> Option<usize>,
) -> AppResult<()> {
    let width = kind.pointer_width();

    for (index, group) in plan.groups.iter().enumerate() {
        let lookup = read_u32(payload, descriptor_offset(plan, index)?)?
            .checked_sub(section_rva)
            .ok_or_else(|| AppError::new("import lookup table lies before its section"))?
            as usize;

        for entry in 0..group.entries.len() {
            let Some(slot) = u32::try_from(entry.saturating_mul(width))
                .ok()
                .and_then(|delta| group.first_thunk.checked_add(delta))
                .and_then(&slot_offset)
            else {
                continue;
            };
            if read_pointer(output, slot, kind)? != 0 {
                continue;
            }

            let thunk = read_pointer(
                payload,
                lookup.saturating_add(entry.saturating_mul(width)),
                kind,
            )?;
            write_pointer(output, slot, kind, thunk as u64)?; // loader stops at zero slot
        }
    }

    Ok(())
}

fn bound_table_in_slack(
    output: &[u8],
    model: &PeModel,
    table_end: usize,
    header_limit: usize,
) -> AppResult<Option<Range<usize>>> {
    let Some(directory) = model.directory(output, BOUND_IMPORT_DIRECTORY) else {
        return Ok(None);
    };

    let start = directory.rva().as_usize();
    let end = start.saturating_add(directory.size() as usize);
    let in_slack = start >= table_end && end <= header_limit && end <= output.len();

    Ok(in_slack.then_some(start..end))
}

fn clear_bound_imports(
    output: &mut [u8],
    model: &PeModel,
    bound_table: Option<Range<usize>>,
    slot: &Range<usize>,
) -> AppResult<bool> {
    let overlapping = bound_table.filter(|table| table.start < slot.end && slot.start < table.end);

    if let Some(table) = overlapping.and_then(|table| output.get_mut(table)) {
        table.fill(0);
    }

    Ok(model.clear_directory(output, BOUND_IMPORT_DIRECTORY)) // stale once descriptors move
}

fn write_mempe_section_header(
    output: &mut [u8],
    section_header: usize,
    virtual_address: u32,
    virtual_size: usize,
    raw_offset: usize,
    raw_size: usize,
) -> AppResult<()> {
    let header = output
        .get_mut(section_header..section_header.saturating_add(SECTION_HEADER_SIZE))
        .ok_or_else(|| AppError::new("new section header lies outside the PE headers"))?;
    header.fill(0);
    header
        .get_mut(..SECTION_NAME_SIZE)
        .ok_or_else(|| AppError::new("new section name lies outside the PE headers"))?
        .copy_from_slice(b".mempe\0\0");
    write_u32(
        output,
        section_header.saturating_add(SECTION_VIRTUAL_SIZE_OFFSET),
        u32::try_from(virtual_size)
            .map_err(|_| AppError::new("import payload size exceeds u32"))?,
    )?;
    write_u32(
        output,
        section_header.saturating_add(SECTION_RVA_OFFSET),
        virtual_address,
    )?;
    write_u32(
        output,
        section_header.saturating_add(SECTION_RAW_SIZE_OFFSET),
        u32::try_from(raw_size).map_err(|_| AppError::new("import raw size exceeds u32"))?,
    )?;
    write_u32(
        output,
        section_header.saturating_add(SECTION_RAW_POINTER_OFFSET),
        u32::try_from(raw_offset).map_err(|_| AppError::new("import file offset exceeds u32"))?,
    )?;
    write_u32(
        output,
        section_header.saturating_add(SECTION_CHARACTERISTICS_OFFSET),
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
    let section_count_offset = model.nt_offset.saturating_add(SECTION_COUNT_OFFSET);
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

    let descriptors = virtual_address as usize;
    let descriptor_size = import_descriptor_bytes(plan)?;
    model
        .set_directory(output, IMPORT_DIRECTORY, descriptors, descriptor_size)
        .ok_or_else(|| AppError::new("PE has no requested data-directory slot"))?;

    if plan.existing.is_empty() && !plan.keep_iat_directory {
        return Ok(model.clear_directory(output, IAT_DIRECTORY));
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

        write_import_descriptor(
            &mut payload,
            descriptor_offset(plan, group_index)?,
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
        write_pointer(payload, thunk_offset, kind, thunk)?;
    }

    Ok(())
}

fn ordinal_thunk(kind: PeKind, ordinal: u32) -> u64 {
    kind.ordinal_flag() | u64::from(ordinal & 0xffff)
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
        descriptor.saturating_add(IMPORT_NAME_OFFSET),
        payload_rva(section_rva, module_offset, "import module")?,
    )?;
    write_u32(
        payload,
        descriptor.saturating_add(IMPORT_IAT_OFFSET),
        first_thunk,
    )
}

// the descriptors the plan keeps come first
fn descriptor_offset(plan: &ImportPlan, index: usize) -> AppResult<usize> {
    index
        .checked_mul(IMPORT_DESCRIPTOR_SIZE)
        .and_then(|offset| offset.checked_add(plan.existing.len()))
        .ok_or_else(|| AppError::new("import descriptor offset overflowed"))
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
