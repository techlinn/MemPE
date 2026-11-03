use super::exception::{
    EXCEPTION_DIRECTORY, RUNTIME_FUNCTION_SIZE, runtime_function_is_valid, unwind_layout,
};
use super::sections::readable_section_name;
use super::{PAGE_SIZE, SectionLayout};
use crate::pe::image::{read_pointer, read_u32};
use crate::pe::{IMAGE_SCN_MEM_EXECUTE, PeImage, PeKind, PeModel, RegionEvidence, Rva};

const PDATA_NAME: &[u8; 8] = b".pdata\0\0";
const MAX_PDATA_ENTRIES: usize = 65_536;
const TLS_DIRECTORY: usize = 9;
const MAX_TLS_CALLBACKS: usize = 1_024;
const PAGE_RESIDENT: u8 = 0b01;
const PAGE_PRIVATE: u8 = 0b10;
const HIGH_ENTROPY_THRESHOLD: f64 = 7.2;
const MIN_ENTROPY_SECTION_BYTES: usize = 1024;
const MIN_ABSENT_SECTION_BYTES: usize = 1024;
const ENTROPY_ALPHABET: usize = 256;

pub(super) fn count_write_execute_sections(
    layouts: &[SectionLayout<'_>],
    regions: &[RegionEvidence],
) -> usize {
    layouts
        .iter()
        .filter(|layout| {
            let start = layout.model.virtual_address.get() as usize;
            let end = start.saturating_add(layout.source_length);
            regions.iter().any(|region| {
                region.writable
                    && region.executable
                    && region.offset < end
                    && start < region.offset.saturating_add(region.size)
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
    if layout.model.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
        return false;
    }
    if layout.source_length < MIN_ABSENT_SECTION_BYTES {
        return false;
    }
    let start = layout.model.virtual_address.get() as usize;
    let Some(slice) = memory.get(start..start.saturating_add(layout.source_length)) else {
        return false;
    };
    slice.iter().all(|byte| *byte == 0)
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
    let start = layout.model.virtual_address.get() as usize;
    let Some(slice) = memory.get(start..start.saturating_add(layout.source_length)) else {
        return false;
    };
    let trimmed = trim_trailing_zeroes(slice);
    if trimmed.len() < MIN_ENTROPY_SECTION_BYTES {
        return false;
    }
    let first_page = start / PAGE_SIZE;
    let page_count = layout.source_length.div_ceil(PAGE_SIZE);
    let Some(pages) = page_flags.get(first_page..first_page.saturating_add(page_count)) else {
        return false;
    };
    if !pages.iter().any(|flags| flags & PAGE_RESIDENT != 0) {
        return false;
    }
    if pages.iter().any(|flags| flags & PAGE_PRIVATE != 0) {
        return false;
    }
    shannon_entropy(trimmed) >= HIGH_ENTROPY_THRESHOLD
}

pub(super) fn invalid_pdata_sections(
    output: &[u8],
    model: &PeModel,
    layouts: &[SectionLayout<'_>],
    header_size: usize,
) -> usize {
    let declared = exception_rva(output, model);
    layouts
        .iter()
        .filter(|layout| layout.model.name() == PDATA_NAME)
        .filter(|layout| !holds_rva(layout, declared))
        .filter(|layout| unwind_table_is_bogus(output, model, layouts, header_size, layout))
        .count()
}

fn exception_rva(output: &[u8], model: &PeModel) -> Option<u32> {
    let offset = model.directory_offset(EXCEPTION_DIRECTORY).ok()??;
    let rva = read_u32(output, offset).ok()?;
    (rva != 0).then_some(rva)
}

fn holds_rva(layout: &SectionLayout<'_>, rva: Option<u32>) -> bool {
    let Some(rva) = rva else {
        return false;
    };
    let start = layout.model.virtual_address.get() as usize;
    let rva = rva as usize;
    rva >= start && rva < start.saturating_add(layout.source_length)
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
    let unwind = unwind_layout(output, model);
    let count = (layout.source_length / RUNTIME_FUNCTION_SIZE).min(MAX_PDATA_ENTRIES);
    let mut invalid = 0usize;
    for index in 0..count {
        let offset = layout
            .raw_offset
            .saturating_add(index.saturating_mul(RUNTIME_FUNCTION_SIZE));
        let Some(entry) = output.get(offset..offset.saturating_add(RUNTIME_FUNCTION_SIZE)) else {
            break;
        };
        if !runtime_function_is_valid(output, entry, model, layouts, header_size, unwind) {
            invalid = invalid.saturating_add(1);
        }
    }
    count > 0 && invalid > count / 2
}

fn trim_trailing_zeroes(bytes: &[u8]) -> &[u8] {
    let Some(last) = bytes.iter().rposition(|byte| *byte != 0) else {
        return &[];
    };
    bytes.get(..=last).unwrap_or(bytes)
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; ENTROPY_ALPHABET];
    for byte in bytes {
        if let Some(count) = counts.get_mut(usize::from(*byte)) {
            *count = count.saturating_add(1);
        }
    }
    let total = bytes.len() as f64;
    let mut entropy = 0.0f64;
    for count in counts {
        if count == 0 {
            continue;
        }
        let share = f64::from(count) / total;
        entropy -= share * share.log2();
    }
    entropy
}

pub(super) fn count_tls_callbacks(image: &PeImage<'_>, observed_base: usize) -> usize {
    let Ok(Some(directory)) = image.directory(TLS_DIRECTORY) else {
        return 0;
    };
    let model = image.model();
    let memory = image.bytes();
    let width: usize = if model.kind() == PeKind::Pe32 { 4 } else { 8 };
    let Some(table_offset) = width
        .checked_mul(3)
        .and_then(|offset| directory.rva().as_usize().checked_add(offset))
    else {
        return 0;
    };
    let Ok(table) = read_pointer(memory, table_offset, model.kind()) else {
        return 0;
    };
    let Some(table_rva) = table.checked_sub(observed_base) else {
        return 0;
    };
    let mut count = 0usize;
    for index in 0..MAX_TLS_CALLBACKS {
        let Some(offset) = index
            .checked_mul(width)
            .and_then(|offset| table_rva.checked_add(offset))
        else {
            break;
        };
        match read_pointer(memory, offset, model.kind()) {
            Ok(0) | Err(_) => break,
            Ok(_) => count = count.saturating_add(1),
        }
    }
    count
}

pub(super) fn entry_section_name(
    layouts: &[SectionLayout<'_>],
    entry_point: u32,
) -> Option<String> {
    let rva = Rva(entry_point);
    let (index, layout) = layouts
        .iter()
        .enumerate()
        .find(|(_, layout)| layout.model.contains_rva(rva))?;
    let name = readable_section_name(layout.model.name(), index.saturating_add(1))
        .unwrap_or(*layout.model.name());
    let end = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name.len());
    let label = String::from_utf8_lossy(name.get(..end)?).into_owned();
    (!label.is_empty()).then_some(label)
}
