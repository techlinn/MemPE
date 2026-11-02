use super::{
    IMAGE_SCN_CNT_CODE, MAX_OUTPUT_SIZE, PAGE_SIZE, SECTION_HEADER_SIZE, SectionLayout, align_up,
};
use crate::pe::image::{first_section_rva, write_u32};
use crate::pe::{
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, PeModel, RegionEvidence,
};
use crate::{AppError, AppResult};

const SECTION_NAME_SIZE: usize = 8;
const PRINTABLE_FIRST: u8 = 0x20;
const PRINTABLE_LAST: u8 = 0x7e;
const MAX_RENAME_ATTEMPTS: usize = 64;

pub(super) fn build_output_buffer<'a>(
    model: &'a PeModel,
    memory: &[u8],
    reserve_import_header: bool,
) -> AppResult<(Vec<u8>, Vec<SectionLayout<'a>>, usize)> {
    let section_table_end = model
        .sections
        .last()
        .map(|section| section.header_offset.saturating_add(SECTION_HEADER_SIZE))
        .ok_or_else(|| AppError::new("PE has no section headers"))?;
    let header_size = header_size(model, section_table_end, reserve_import_header)?;
    let layouts = layout_sections(model, memory, header_size)?;
    let output_size = layouts
        .iter()
        .map(|layout| layout.raw_offset.saturating_add(layout.raw_size))
        .max()
        .unwrap_or(header_size)
        .max(header_size);
    if output_size > MAX_OUTPUT_SIZE {
        return Err(AppError::new(
            "rebuilt PE exceeds the 1 GiB output safety limit",
        ));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(output_size)
        .map_err(|_| AppError::new("not enough memory for the rebuilt PE"))?;
    output.resize(output_size, 0);
    let copied_headers = header_size.min(memory.len());
    output[..copied_headers].copy_from_slice(&memory[..copied_headers]);
    Ok((output, layouts, header_size))
}

fn header_size(
    model: &PeModel,
    section_table_end: usize,
    reserve_import_header: bool,
) -> AppResult<usize> {
    let alignment = model.file_alignment as usize;
    let minimum = align_up(section_table_end, alignment)?;
    if !reserve_import_header {
        return Ok(minimum);
    }

    let next_header_end = section_table_end.saturating_add(SECTION_HEADER_SIZE); // the .mempe header
    let with_room = align_up(next_header_end, alignment)?;
    let first_section = first_section_rva(&model.sections).unwrap_or(usize::MAX);
    Ok(if with_room <= first_section {
        with_room
    } else {
        minimum
    })
}

pub(super) fn write_sections(
    output: &mut [u8],
    memory: &[u8],
    layouts: &[SectionLayout<'_>],
) -> AppResult<usize> {
    let mut renamed = 0usize;
    for (index, layout) in layouts.iter().enumerate() {
        let header = layout.model.header_offset;
        if let Some(name) = unique_replacement_name(layouts, index) {
            output
                .get_mut(header..header.saturating_add(SECTION_NAME_SIZE))
                .ok_or_else(|| AppError::new("section name lies outside the rebuilt PE"))?
                .copy_from_slice(&name);
            renamed = renamed.saturating_add(1);
        }
        write_u32(
            output,
            header.saturating_add(16),
            u32::try_from(layout.raw_size)
                .map_err(|_| AppError::new("section raw size does not fit a PE field"))?,
        )?;
        write_u32(
            output,
            header.saturating_add(20),
            u32::try_from(layout.raw_offset)
                .map_err(|_| AppError::new("section file offset does not fit a PE field"))?,
        )?;
        if layout.raw_size == 0 {
            continue;
        }
        let source_offset = layout.model.virtual_address.get() as usize;
        let source_end = source_offset
            .checked_add(layout.source_length)
            .ok_or_else(|| AppError::new("section source range overflowed"))?;
        let destination_end = layout
            .raw_offset
            .checked_add(layout.source_length)
            .ok_or_else(|| AppError::new("section output range overflowed"))?;
        let source = memory
            .get(source_offset..source_end)
            .ok_or_else(|| AppError::new("section source range is outside captured memory"))?;
        output
            .get_mut(layout.raw_offset..destination_end)
            .ok_or_else(|| AppError::new("section output range is outside rebuilt PE"))?
            .copy_from_slice(source);
    }
    Ok(renamed)
}

pub(super) fn recover_section_headers(
    memory: &[u8],
    model: &PeModel,
    regions: &[RegionEvidence],
) -> AppResult<Option<Vec<u8>>> {
    if regions.is_empty() {
        return Ok(None);
    }
    let mut sections = model.sections.iter().collect::<Vec<_>>();
    sections.sort_unstable_by_key(|section| section.virtual_address);
    let mut recovered = None;
    let mut image_end = model.image_size as usize;
    for (index, section) in sections.iter().enumerate() {
        let start = section.virtual_address.get() as usize;
        let limit = sections
            .get(index + 1)
            .map(|next| next.virtual_address.get() as usize)
            .unwrap_or(model.image_size as usize)
            .min(memory.len());
        if start >= limit {
            continue;
        }
        let declared = section.virtual_size.max(section.raw_size) as usize;
        let expanded = expanded_section_length(memory, regions, start, limit, declared);
        let section_end = start.saturating_add(expanded).min(limit);
        let characteristics =
            recovered_characteristics(section.characteristics, regions, start, section_end);
        if expanded > declared {
            let virtual_size = u32::try_from(expanded)
                .map_err(|_| AppError::new("recovered section size exceeds u32"))?;
            let output = recovered.get_or_insert_with(|| memory.to_vec());
            write_u32(
                output,
                section.header_offset.saturating_add(8),
                virtual_size,
            )?;
            image_end = image_end.max(start.saturating_add(expanded));
        }
        if characteristics != section.characteristics {
            let output = recovered.get_or_insert_with(|| memory.to_vec());
            write_u32(
                output,
                section.header_offset.saturating_add(36),
                characteristics,
            )?;
        }
    }
    if image_end > model.image_size as usize {
        let image_size = align_up(image_end, model.section_alignment as usize)?;
        let image_size = u32::try_from(image_size)
            .map_err(|_| AppError::new("recovered image size exceeds u32"))?;
        let output = recovered.get_or_insert_with(|| memory.to_vec());
        write_u32(output, model.size_of_image_offset, image_size)?;
    }
    Ok(recovered)
}

fn expanded_section_length(
    memory: &[u8],
    regions: &[RegionEvidence],
    start: usize,
    limit: usize,
    declared: usize,
) -> usize {
    let scan_start = start.saturating_add(declared).min(limit);
    let mut last_byte = scan_start;
    for region in regions.iter().filter(|region| region.readable) {
        let region_end = region.offset.saturating_add(region.size);
        let range_start = scan_start.max(region.offset);
        let range_end = limit.min(region_end).min(memory.len());
        if range_start >= range_end {
            continue;
        }
        let Some(bytes) = memory.get(range_start..range_end) else {
            continue;
        };
        if let Some(index) = bytes.iter().rposition(|byte| *byte != 0) {
            last_byte = last_byte.max(range_start.saturating_add(index).saturating_add(1));
        }
    }
    last_byte.saturating_sub(start).max(declared)
}

fn recovered_characteristics(
    characteristics: u32,
    regions: &[RegionEvidence],
    start: usize,
    end: usize,
) -> u32 {
    let coverage = ProtectionCoverage::measure(regions, start, end);
    let mut recovered = characteristics;
    if coverage.executable > 0 {
        recovered |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
    }
    if coverage.readable > 0 {
        recovered |= IMAGE_SCN_MEM_READ;
    }
    if coverage.write_is_substantial(end.saturating_sub(start)) {
        recovered |= IMAGE_SCN_MEM_WRITE;
    }
    recovered
}

#[derive(Default)]
struct ProtectionCoverage {
    committed: usize,
    readable: usize,
    writable: usize,
    executable: usize,
}

impl ProtectionCoverage {
    fn measure(regions: &[RegionEvidence], start: usize, end: usize) -> Self {
        let mut coverage = Self::default();
        for region in regions {
            let region_end = region.offset.saturating_add(region.size);
            let overlap_start = start.max(region.offset);
            let overlap_end = end.min(region_end);
            let bytes = overlap_end.saturating_sub(overlap_start);
            if bytes == 0 {
                continue;
            }
            coverage.committed = coverage.committed.saturating_add(bytes);
            if region.readable {
                coverage.readable = coverage.readable.saturating_add(bytes);
            }
            if region.writable {
                coverage.writable = coverage.writable.saturating_add(bytes);
            }
            if region.executable {
                coverage.executable = coverage.executable.saturating_add(bytes);
            }
        }
        coverage
    }

    fn write_is_substantial(&self, section_size: usize) -> bool {
        if self.committed == 0 || self.writable == 0 {
            return false;
        }
        let unanimous = self.writable >= section_size && self.committed >= section_size;
        let substantial = self.writable >= PAGE_SIZE.saturating_mul(2)
            && self.writable.saturating_mul(2) >= section_size;
        unanimous || substantial
    }
}

fn layout_sections<'a>(
    model: &'a PeModel,
    memory: &[u8],
    header_size: usize,
) -> AppResult<Vec<SectionLayout<'a>>> {
    let mut sections = model.sections.iter().collect::<Vec<_>>();
    sections.sort_unstable_by_key(|section| section.virtual_address);
    let mut layouts = Vec::with_capacity(sections.len());
    let mut raw_offset = header_size;
    for (index, section) in sections.iter().enumerate() {
        let source_offset = section.virtual_address.get() as usize;
        let declared_length = section.virtual_size.max(section.raw_size) as usize;
        let next_rva = sections
            .get(index + 1)
            .map(|next| next.virtual_address.get() as usize)
            .unwrap_or(memory.len());
        let until_next = next_rva.saturating_sub(source_offset);
        let available = memory.len().saturating_sub(source_offset);
        let source_length = declared_length.min(until_next).min(available);
        let raw_size =
            if source_length == 0 || section_is_zero(memory, source_offset, source_length) {
                0
            } else {
                align_up(source_length, model.file_alignment as usize)?
            };
        layouts.push(SectionLayout {
            model: section,
            source_length,
            raw_offset: if raw_size == 0 { 0 } else { raw_offset },
            raw_size,
        });
        raw_offset = raw_offset
            .checked_add(raw_size)
            .ok_or_else(|| AppError::new("rebuilt section layout overflowed"))?;
    }
    Ok(layouts)
}

fn section_is_zero(memory: &[u8], offset: usize, length: usize) -> bool {
    memory
        .get(offset..offset.saturating_add(length))
        .is_some_and(|slice| slice.iter().all(|byte| *byte == 0))
}

fn unique_replacement_name(layouts: &[SectionLayout<'_>], index: usize) -> Option<[u8; 8]> {
    let current = layouts.get(index)?;
    let mut position = index.saturating_add(1);
    for _attempt in 0..MAX_RENAME_ATTEMPTS {
        let candidate = readable_section_name(current.model.name(), position)?;
        let taken = layouts
            .iter()
            .enumerate()
            .any(|(other, layout)| other != index && layout.model.name() == &candidate);
        if !taken {
            return Some(candidate);
        }
        position = position.saturating_add(layouts.len());
    }
    None
}

pub(super) fn readable_section_name(name: &[u8; 8], position: usize) -> Option<[u8; 8]> {
    let end = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name.len());
    let label = name.get(..end)?;
    let readable = label
        .iter()
        .all(|byte| (PRINTABLE_FIRST..=PRINTABLE_LAST).contains(byte))
        && label.iter().any(|byte| *byte != b' ');
    if readable {
        return None;
    }
    let text = format!(".sec{position:02}");
    let bytes = text.as_bytes();
    let mut replacement = [0u8; SECTION_NAME_SIZE];
    replacement.get_mut(..bytes.len())?.copy_from_slice(bytes);
    Some(replacement)
}

#[cfg(test)]
mod tests {
    use super::{
        IMAGE_SCN_MEM_WRITE, RegionEvidence, readable_section_name, recovered_characteristics,
        section_is_zero,
    };

    #[test]
    fn treats_only_an_all_zero_range_as_empty() {
        let memory = [0u8, 0, 0, 0, 7, 0, 0, 0];

        assert!(section_is_zero(&memory, 0, 4));
        assert!(!section_is_zero(&memory, 0, 8));
        assert!(!section_is_zero(&memory, 4, 1));
        assert!(section_is_zero(&memory, 5, 3));
        assert!(!section_is_zero(&memory, 4, 99));
        assert!(section_is_zero(&memory, 0, 0));
    }

    #[test]
    fn replaces_only_unreadable_section_names() {
        let printable = readable_section_name(b".text\0\0\0", 1);
        let empty = readable_section_name(b"\0\0\0\0\0\0\0\0", 3);
        let binary = readable_section_name(&[0xE7, 0x91, 0x2A, 0, 0, 0, 0, 0], 7);
        let blank = readable_section_name(b"        ", 2);

        assert_eq!(printable, None);
        assert_eq!(empty, Some(*b".sec03\0\0"));
        assert_eq!(binary, Some(*b".sec07\0\0"));
        assert_eq!(blank, Some(*b".sec02\0\0"));
    }

    #[test]
    fn requires_substantial_write_coverage() {
        let mut regions = [
            RegionEvidence {
                offset: 0x1000,
                size: 0x1000,
                readable: true,
                writable: true,
                executable: false,
            },
            RegionEvidence {
                offset: 0x2000,
                size: 0x3000,
                readable: true,
                writable: false,
                executable: false,
            },
        ];

        let sparse = recovered_characteristics(0, &regions, 0x1000, 0x5000);
        let retained = recovered_characteristics(IMAGE_SCN_MEM_WRITE, &regions, 0x1000, 0x5000);
        regions[0].size = 0x2000;
        regions[1].offset = 0x3000;
        regions[1].size = 0x2000;
        let substantial = recovered_characteristics(0, &regions, 0x1000, 0x5000);

        assert_eq!(sparse & IMAGE_SCN_MEM_WRITE, 0);
        assert_ne!(retained & IMAGE_SCN_MEM_WRITE, 0);
        assert_ne!(substantial & IMAGE_SCN_MEM_WRITE, 0);
    }
}
