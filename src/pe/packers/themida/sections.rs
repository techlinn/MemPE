use std::ops::Range;

use super::Packed;
use crate::pe::image::{read_u16, read_u32, write_u32};
use crate::pe::packers::PackerReport;
use crate::pe::packers::tables::{
    RELOCATION_SECTION, SECTION_CHARACTERISTICS_OFFSET, SECTION_COUNT_OFFSET, SectionPiece,
    clear_directory, cut_tail, drop_relocation_blocks, evacuate, keep_unwind_within, shed,
    table_references,
};
use crate::pe::{
    BASERELOC_DIRECTORY, DELAY_IMPORT_DIRECTORY, EXCEPTION_DIRECTORY, IMPORT_DIRECTORY,
    RESOURCE_DIRECTORY, SectionModel,
};

const SECTION_NAME_LENGTH: usize = 8;
const SECTION_WRITABLE: u32 = 0x8000_0000;
const MOVED_TABLES_SECTION: &[u8; 8] = b".tmdtab\0";

pub(super) struct Tables {
    pub(super) iat: Option<usize>,
    pub(super) entry: Option<usize>,
    pub(super) relocations: Option<usize>,
    pub(super) linked: Vec<SectionPiece>,
}

pub(super) fn name(restored: &mut [u8], packed: &Packed<'_>, tables: &Tables) -> bool {
    let model = packed.model();
    let directory = |index| {
        model
            .directory(restored, index)
            .ok()
            .flatten()
            .map(|directory| directory.rva().as_usize())
    };
    let resources = directory(RESOURCE_DIRECTORY);
    let delayed = directory(DELAY_IMPORT_DIRECTORY);
    let first_code = model
        .sections()
        .iter()
        .filter(|section| section.is_executable())
        .map(|section| section.virtual_address().as_usize())
        .min();
    let mut named = false;

    for section in model.sections() {
        let range = section.range();
        let header = section.header_offset;
        if range.start >= packed.layout.original_end {
            continue;
        }

        let holds = |rva: Option<usize>| rva.is_some_and(|rva| range.contains(&rva));
        if holds(tables.relocations) {
            let flags = header + SECTION_CHARACTERISTICS_OFFSET;
            let _ = write_u32(restored, flags, RELOCATION_SECTION); // themida drops the discardable flag
        }

        let blank = section.name().iter().all(|byte| matches!(byte, 0 | b' ')); // themida overwrites the program's names with spaces
        if !blank {
            continue;
        }

        let linked = tables
            .linked
            .iter()
            .find(|piece| piece.start == range.start);
        let writable = section.characteristics() & SECTION_WRITABLE != 0;
        let second_code = section.is_executable() && Some(range.start) != first_code;

        let name: &[u8] = match linked {
            Some(piece) => &piece.name,
            None if second_code && holds(tables.entry) => b".itext", // delphi starts the program from a second code section of its own
            None if section.is_executable() => b".text",
            None if holds(tables.relocations) => b".reloc",
            None if holds(resources) => b".rsrc",
            None if holds(delayed) => b".didata",
            None if writable && holds(tables.iat) => b".idata", // borland linkers give the imports a writable section of their own
            None if writable => b".data",
            None => b".rdata",
        };

        let Some(field) = restored.get_mut(header..header + SECTION_NAME_LENGTH) else {
            continue;
        };
        let length = name.len().min(SECTION_NAME_LENGTH);
        field.fill(0);
        field[..length].copy_from_slice(&name[..length]);
        named = true;
    }

    named
}

pub(super) fn drop_engine(restored: &mut Vec<u8>, packed: &Packed<'_>, report: &mut PackerReport) {
    let model = packed.model();
    let tail = packed.tail();
    let entry = read_u32(restored, model.entry_point_offset).map(|entry| entry as usize);
    if entry.is_ok_and(|entry| tail.contains(&entry)) {
        report
            .unrestored
            .push("themida's sections (the entry point still runs in them)");
        return;
    }

    let in_tail = |restored: &[u8], index| {
        model
            .directory(restored, index)
            .ok()
            .flatten()
            .is_some_and(|directory| tail.contains(&directory.rva().as_usize()))
    };
    if in_tail(restored, IMPORT_DIRECTORY) {
        clear_directory(restored, model, IMPORT_DIRECTORY); // themida's own few imports, the rebuild tables the program's from the iat
    }
    if in_tail(restored, BASERELOC_DIRECTORY) {
        let _ = drop_relocation_blocks(restored, model, std::slice::from_ref(&tail)); // the stub table only fixes themida's pages
    }
    if in_tail(restored, EXCEPTION_DIRECTORY) {
        let _ = keep_unwind_within(restored, model, packed.code());
    }

    let sections = section_count(restored, packed);
    let program = 0..packed.layout.original_end;
    if !evacuate(restored, model, &program, &tail, MOVED_TABLES_SECTION) {
        report
            .unrestored
            .push("themida's sections (a table they hold had nowhere to move to)");
        return;
    }

    let referenced = table_references(restored, model, packed.origin.base);
    let pinned = referenced.iter().any(|rva| tail.contains(rva));
    let appended = section_count(restored, packed) != sections; // a table moved past the tail keeps it from being cut off
    let cut = match pinned || appended {
        true => None,
        false => cut_tail(restored, model, tail.start),
    };
    let dropped = cut.unwrap_or_else(|| {
        let unused: Vec<Range<usize>> = model
            .sections()
            .iter()
            .map(SectionModel::range)
            .filter(|range| range.start >= tail.start)
            .filter(|range| !referenced.iter().any(|rva| range.contains(rva)))
            .collect();
        shed(restored, model, &unused)
    });

    if pinned {
        report.unrestored.push(
            "some of themida's sections (a table moved out of them still points at data they hold)",
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
