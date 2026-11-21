use super::RegionProtection;
use super::exceptions::{is_managed, runtime_function_is_valid};
use super::sections::section_is_zero;
use super::{PAGE_SIZE, SectionLayout};
use crate::pe::bytes::entropy;
use crate::pe::{
    EXCEPTION_DIRECTORY, PeKind, PeModel, RUNTIME_FUNCTION_SIZE, Rva, SECTION_NAME_SIZE,
};
use crate::pe::{PAGE_PRIVATE, PAGE_RESIDENT};

const PDATA_NAME: &[u8; 8] = b".pdata\0\0";
const MAX_PDATA_ENTRIES: usize = 65_536;
const HIGH_ENTROPY_THRESHOLD: f64 = 7.2;
const MIN_ENTROPY_BYTES: usize = 1024;
const MIN_ABSENT_SECTION_BYTES: usize = 1024;

pub(super) fn count_write_execute_sections(
    layouts: &[SectionLayout<'_>],
    regions: &[RegionProtection],
) -> usize {
    layouts
        .iter()
        .filter(|layout| {
            let range = layout.virtual_range();
            regions.iter().any(|region| {
                region.writable
                    && region.executable
                    && region.offset < range.end
                    && range.start < region.offset.saturating_add(region.size)
            })
        })
        .count()
}

pub(super) fn absent_sections(memory: &[u8], layouts: &[SectionLayout<'_>]) -> usize {
    layouts
        .iter()
        .filter(|layout| section_absent(memory, layout))
        .count()
}

fn section_absent(memory: &[u8], layout: &SectionLayout<'_>) -> bool {
    layout.model.is_executable()
        && layout.source_length >= MIN_ABSENT_SECTION_BYTES
        && section_is_zero(memory, layout.virtual_range().start, layout.source_length)
}

pub(super) fn never_decrypted_sections(
    memory: &[u8],
    layouts: &[SectionLayout<'_>],
    page_flags: &[u8],
) -> usize {
    layouts
        .iter()
        .filter(|layout| section_never_decrypted(memory, layout, page_flags))
        .count()
}

fn section_never_decrypted(memory: &[u8], layout: &SectionLayout<'_>, page_flags: &[u8]) -> bool {
    if !layout.model.is_executable() {
        return false;
    }

    let range = layout.virtual_range();
    let start = range.start;
    let Some(slice) = memory.get(range) else {
        return false;
    };

    has_unwritten_high_entropy_page(slice, start, page_flags)
}

// heuristic: entropy says nothing certain about encryption
fn has_unwritten_high_entropy_page(section: &[u8], start: usize, page_flags: &[u8]) -> bool {
    let mut offset = 0usize;

    while let Some(rest) = section.get(offset..).filter(|rest| !rest.is_empty()) {
        let address = start.saturating_add(offset);
        let page = address / PAGE_SIZE;
        let in_page = PAGE_SIZE
            .saturating_sub(address % PAGE_SIZE)
            .min(rest.len());
        let bytes = rest.get(..in_page).unwrap_or(rest);
        let flags = page_flags.get(page).copied().unwrap_or(0);
        offset = offset.saturating_add(in_page);

        if flags & PAGE_RESIDENT == 0 || flags & PAGE_PRIVATE != 0 {
            continue;
        }

        let trimmed = trim_trailing_zeroes(bytes);

        if trimmed.len() >= MIN_ENTROPY_BYTES && entropy(trimmed) >= HIGH_ENTROPY_THRESHOLD {
            return true;
        }
    }

    false
}

pub(super) fn invalid_pdata_sections(
    output: &[u8],
    model: &PeModel,
    layouts: &[SectionLayout<'_>],
    header_size: usize,
) -> usize {
    if model.kind == PeKind::Pe32 {
        return 0; // x86: no unwind table
    }

    let declared = model
        .directory(output, EXCEPTION_DIRECTORY)
        .map(|directory| directory.rva().get());

    layouts
        .iter()
        .filter(|layout| layout.model.name() == PDATA_NAME)
        .filter(|layout| !holds_rva(layout, declared))
        .filter(|layout| unwind_table_is_bogus(output, model, layouts, header_size, layout))
        .count()
}

fn holds_rva(layout: &SectionLayout<'_>, rva: Option<u32>) -> bool {
    rva.is_some_and(|rva| layout.virtual_range().contains(&(rva as usize)))
}

fn unwind_table_is_bogus(
    output: &[u8],
    model: &PeModel,
    layouts: &[SectionLayout<'_>],
    header_size: usize,
    layout: &SectionLayout<'_>,
) -> bool {
    if layout.raw_size == 0 {
        return false;
    }

    let table_end = layout.raw_offset.saturating_add(layout.source_length);
    let Some(table) = output.get(layout.raw_offset..table_end) else {
        return false;
    };

    let managed = is_managed(output, model);
    let count = used_entries(table).min(MAX_PDATA_ENTRIES);
    let invalid = table
        .chunks(RUNTIME_FUNCTION_SIZE)
        .take(count)
        .filter(|entry| {
            !runtime_function_is_valid(output, entry, model, layouts, header_size, managed)
        })
        .count();

    count > 0 && invalid > count / 2
}

fn used_entries(table: &[u8]) -> usize {
    trim_trailing_zeroes(table)
        .len()
        .div_ceil(RUNTIME_FUNCTION_SIZE) // padding is not an entry
}

fn trim_trailing_zeroes(bytes: &[u8]) -> &[u8] {
    let Some(last) = bytes.iter().rposition(|byte| *byte != 0) else {
        return &[];
    };

    bytes.get(..=last).unwrap_or(bytes)
}

pub(super) fn entry_section_name(
    output: &[u8],
    layouts: &[SectionLayout<'_>],
    entry_point: u32,
) -> Option<String> {
    let rva = Rva(entry_point);
    let layout = layouts
        .iter()
        .find(|layout| layout.model.contains_rva(rva))?;
    let header = layout.model.header_offset;
    let name = output.get(header..header.saturating_add(SECTION_NAME_SIZE))?;
    let end = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name.len());
    let label = String::from_utf8_lossy(name.get(..end)?).into_owned();

    (!label.is_empty()).then_some(label)
}
