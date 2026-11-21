use std::ops::Range;

use super::Packed;
use crate::pe::IMAGE_SCN_MEM_WRITE;
use crate::pe::SECTION_NAME_SIZE;
use crate::pe::UNWIND_INFO_OFFSET;
use crate::pe::bytes::{read_pointer, read_u16, read_u32, write_u32};
use crate::pe::{
    BASERELOC_DIRECTORY, DELAY_IMPORT_DIRECTORY, EXCEPTION_DIRECTORY, IMAGE_SCN_MEM_DISCARDABLE,
    IMPORT_DIRECTORY, RESOURCE_DIRECTORY, SECTION_CHARACTERISTICS_OFFSET, SECTION_COUNT_OFFSET,
    SectionModel, TLS_DIRECTORY,
};
use crate::unpack::tables::{
    PlannedSection, cut_tail, drop_relocation_blocks, evacuate, keep_unwind_within, shed,
    table_references,
};
use crate::unpack::{PackerReport, Part};

const MOVED_TABLES_SECTION: &[u8; 8] = b".tmdtab\0";

pub(super) struct Tables {
    pub(super) iat: Option<usize>,
    pub(super) entry: Option<usize>,
    pub(super) relocations: Option<usize>,
    pub(super) linked: Vec<PlannedSection>,
}

pub(super) enum Named {
    Nothing,
    FromLinker,
    Inferred,
}

pub(super) fn mark_relocations_discardable(
    restored: &mut [u8],
    packed: &Packed<'_>,
    relocations: Option<usize>,
) {
    let Some(relocations) = relocations else {
        return;
    };

    for section in &packed.model().sections {
        let range = section.range();
        if range.start < packed.layout.original_end && range.contains(&relocations) {
            let flags = section.header_offset + SECTION_CHARACTERISTICS_OFFSET;
            let discardable = section.characteristics() | IMAGE_SCN_MEM_DISCARDABLE;
            let _ = write_u32(restored, flags, discardable); // themida drops the flag
        }
    }
}

pub(super) fn name(restored: &mut [u8], packed: &Packed<'_>, tables: &Tables) -> Named {
    let model = packed.model();
    let directory = |index| {
        model
            .directory(restored, index)
            .map(|directory| directory.rva().as_usize())
    };
    let resources = directory(RESOURCE_DIRECTORY);
    let delayed = directory(DELAY_IMPORT_DIRECTORY);
    let unwind = directory(EXCEPTION_DIRECTORY);
    let first_unwind_info = unwind
        .and_then(|table| read_u32(restored, table + UNWIND_INFO_OFFSET).ok())
        .map(|info| info as usize);
    let tls_template = directory(TLS_DIRECTORY)
        .and_then(|tls| read_pointer(restored, tls, packed.kind()).ok())
        .and_then(|template| template.checked_sub(packed.origin.base));

    let first_code = model
        .sections
        .iter()
        .filter(|section| section.is_executable())
        .map(|section| section.virtual_address().as_usize())
        .min();
    let mut named = Named::Nothing;
    let mut after_unwind = None;

    for section in &model.sections {
        let range = section.range();
        let header = section.header_offset;
        if range.start >= packed.layout.original_end {
            continue;
        }

        let blank = section.name().iter().all(|byte| matches!(byte, 0 | b' ')); // themida blanks names with spaces
        if !blank {
            continue;
        }

        let linked = tables
            .linked
            .iter()
            .find(|piece| piece.start == range.start);
        let writable = section.characteristics() & IMAGE_SCN_MEM_WRITE != 0;
        let second_code = section.is_executable() && Some(range.start) != first_code;

        let holds = |rva: Option<usize>| rva.is_some_and(|rva| range.contains(&rva));
        let starts_with = |rva: Option<usize>| rva == Some(range.start);
        let follows_unwind = after_unwind == Some(range.start) && holds(first_unwind_info);
        if starts_with(unwind) {
            after_unwind = Some(range.end.next_multiple_of(model.section_alignment as usize));
        }

        let name: &[u8] = match linked {
            Some(piece) => &piece.name,
            None if second_code && holds(tables.entry) => b".itext", // delphi: second code section
            None if section.is_executable() => b".text",
            None if holds(tables.relocations) => b".reloc",
            None if holds(resources) => b".rsrc",
            None if holds(delayed) => b".didata",
            None if starts_with(unwind) => b".pdata",
            None if starts_with(tls_template) => b".tls",
            None if writable && holds(tables.iat) => b".idata", // borland: writable import section
            None if writable => b".data",
            None if holds(tables.iat) && !starts_with(tables.iat) => b".idata", // msvc starts .rdata with the iat, gnu ld does not
            None if follows_unwind => b".xdata", // gnu ld: unwind info right after .pdata
            None => b".rdata",
        };

        let Some(field) = restored.get_mut(header..header + SECTION_NAME_SIZE) else {
            continue;
        };
        let length = name.len().min(SECTION_NAME_SIZE);
        field.fill(0);
        field[..length].copy_from_slice(&name[..length]);
        named = match (linked, named) {
            (Some(_), Named::Nothing | Named::FromLinker) => Named::FromLinker,
            _ => Named::Inferred,
        };
    }

    named
}

pub(super) fn drop_engine(restored: &mut Vec<u8>, packed: &Packed<'_>, report: &mut PackerReport) {
    let model = packed.model();
    let tail = packed.tail();
    let entry = read_u32(restored, model.entry_point_offset).map(|entry| entry as usize);
    if entry.is_ok_and(|entry| tail.contains(&entry)) {
        report.failed_with(Part::PackerSections, "the entry point still runs in them");
        return;
    }

    let in_tail = |restored: &[u8], index| {
        model
            .directory(restored, index)
            .is_some_and(|directory| tail.contains(&directory.rva().as_usize()))
    };
    if in_tail(restored, IMPORT_DIRECTORY) {
        model.clear_directory(restored, IMPORT_DIRECTORY); // themida's imports; rebuild uses iat
    }
    if in_tail(restored, BASERELOC_DIRECTORY) {
        let _ = drop_relocation_blocks(restored, model, std::slice::from_ref(&tail)); // stub table fixes only themida's pages
    }
    if in_tail(restored, EXCEPTION_DIRECTORY) {
        let _ = keep_unwind_within(restored, model, &packed.code);
    }

    let sections = section_count(restored, packed);
    let program = 0..packed.layout.original_end;
    if !evacuate(restored, model, &program, &tail, MOVED_TABLES_SECTION) {
        report.failed_with(
            Part::PackerSections,
            "a table they hold had nowhere to move to",
        );
        return;
    }

    let referenced = table_references(restored, model, packed.origin.base);
    let pinned = referenced.iter().any(|rva| tail.contains(rva));
    let appended = section_count(restored, packed) != sections;
    let cut = match pinned || appended {
        true => None,
        false => cut_tail(restored, model, tail.start),
    };
    let dropped = cut.unwrap_or_else(|| {
        let unused: Vec<Range<usize>> = model
            .sections
            .iter()
            .map(SectionModel::range)
            .filter(|range| range.start >= tail.start)
            .filter(|range| !referenced.iter().any(|rva| range.contains(rva)))
            .collect();
        shed(restored, model, &unused)
    });

    if pinned {
        report.partly_failed(
            Part::PackerSections,
            "a table moved out of them still points at data they hold",
        );
    }
    if dropped > 0 {
        report.notes.push(format!(
            "{} KiB of themida's sections dropped: its loader, virtual machines, import wrappers and the tables it added",
            dropped / 1024
        ));
    }
}

fn section_count(restored: &[u8], packed: &Packed<'_>) -> Option<u16> {
    let count_at = packed.model().nt_offset.checked_add(SECTION_COUNT_OFFSET)?;
    read_u16(restored, count_at).ok()
}
