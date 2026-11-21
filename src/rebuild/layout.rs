use std::ops::Range;

use super::sections::section_is_zero;
use super::{MAX_OUTPUT_SIZE, SECTION_HEADER_SIZE, output_too_large};
use crate::pe::bytes::read_u32;
use crate::pe::{PeModel, SECURITY_DIRECTORY, SectionModel, first_section_rva};
use crate::{AppError, AppResult};

pub(super) struct SectionLayout<'a> {
    pub(super) model: &'a SectionModel,
    pub(super) source_length: usize,
    pub(super) raw_offset: usize,
    pub(super) raw_size: usize,
}

impl SectionLayout<'_> {
    pub(super) fn virtual_range(&self) -> Range<usize> {
        let start = self.model.virtual_address().as_usize();
        start..start.saturating_add(self.source_length)
    }
}

pub(super) fn rva_to_file(
    rva: u32,
    layouts: &[SectionLayout<'_>],
    header_size: usize,
) -> Option<usize> {
    let rva = rva as usize;

    if rva < header_size {
        return Some(rva);
    }

    layouts.iter().find_map(|layout| {
        let range = layout.virtual_range();
        (layout.raw_size != 0 && range.contains(&rva))
            .then(|| layout.raw_offset.saturating_add(rva - range.start))
    })
}

// a section's bytes run until the next section that maps any
pub(super) fn sections_by_rva(model: &PeModel) -> Vec<(&SectionModel, Option<usize>)> {
    let mut sections = model.sections.iter().collect::<Vec<_>>();
    sections.sort_unstable_by_key(|section| section.virtual_address());

    sections
        .iter()
        .enumerate()
        .map(|(index, section)| {
            let next = sections
                .iter()
                .skip(index.saturating_add(1))
                .find(|next| next.mapped_size() != 0)
                .map(|next| next.virtual_address().as_usize());
            (*section, next)
        })
        .collect()
}

pub(super) fn align_up(value: usize, alignment: usize) -> AppResult<usize> {
    let aligned = align_up_u64(value as u64, alignment as u64)?;
    usize::try_from(aligned).map_err(|_| AppError::new("PE alignment overflowed"))
}

pub(super) fn align_up_u64(value: u64, alignment: u64) -> AppResult<u64> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(AppError::new("PE alignment is invalid"));
    }

    value
        .checked_add(alignment - 1)
        .map(|result| result & !(alignment - 1))
        .ok_or_else(|| AppError::new("PE alignment overflowed"))
}

pub(super) fn build_output_buffer<'a>(
    model: &'a PeModel,
    memory: &[u8],
    import_tables: &[Range<usize>],
) -> AppResult<(Vec<u8>, Vec<SectionLayout<'a>>, usize)> {
    let section_table_end = model
        .sections
        .last()
        .map(|section| section.header_offset.saturating_add(SECTION_HEADER_SIZE))
        .ok_or_else(|| AppError::new("PE has no section headers"))?;
    let header_size = header_size(model, memory, section_table_end, !import_tables.is_empty())?;
    let layouts = layout_sections(model, memory, header_size, import_tables)?;
    let over_headers = layouts
        .iter()
        .any(|layout| layout.raw_size != 0 && layout.raw_offset < section_table_end);
    if over_headers {
        return Err(AppError::new(
            "a section's file data overlaps the PE headers the rebuild has to write",
        ));
    }

    let output_size = layouts
        .iter()
        .map(|layout| layout.raw_offset.saturating_add(layout.raw_size))
        .max()
        .unwrap_or(header_size)
        .max(header_size);
    if output_size > MAX_OUTPUT_SIZE {
        return Err(output_too_large("the rebuilt PE", output_size));
    }

    let mut output = Vec::new();
    output
        .try_reserve_exact(output_size)
        .map_err(|_| AppError::new("not enough memory for the rebuilt PE"))?;
    output.resize(output_size, 0);

    let copied_headers = header_size.min(memory.len());
    let source = memory
        .get(..copied_headers)
        .ok_or_else(|| AppError::new("PE headers lie outside captured memory"))?;
    output
        .get_mut(..copied_headers)
        .ok_or_else(|| AppError::new("PE headers lie outside the rebuilt PE"))?
        .copy_from_slice(source);

    Ok((output, layouts, header_size))
}

pub(super) fn header_size(
    model: &PeModel,
    memory: &[u8],
    section_table_end: usize,
    reserve_import_header: bool,
) -> AppResult<usize> {
    let first_section = first_section_rva(&model.sections).unwrap_or(usize::MAX);

    if model.is_low_alignment() {
        return Ok(first_section.min(memory.len()).max(section_table_end)); // low alignment: offset == rva
    }

    let declared = read_u32(memory, model.size_of_headers_offset).map_or(0, |size| size as usize);
    let kept = declared.min(first_section).min(memory.len());
    let used = section_table_end.max(kept);

    let alignment = model.file_alignment as usize;
    let minimum = align_up(used, alignment)?;

    if !reserve_import_header {
        return Ok(minimum);
    }

    let next_header_end = section_table_end.saturating_add(SECTION_HEADER_SIZE); // the .mempe header
    let with_room = align_up(used.max(next_header_end), alignment)?;

    Ok(if with_room <= first_section {
        with_room
    } else {
        minimum
    })
}

pub(super) fn layout_sections<'a>(
    model: &'a PeModel,
    memory: &[u8],
    header_size: usize,
    import_tables: &[Range<usize>],
) -> AppResult<Vec<SectionLayout<'a>>> {
    let mut layouts = Vec::with_capacity(model.sections.len());
    let mut raw_offset = header_size;
    let low_alignment = model.is_low_alignment();
    let directories = directory_ranges(model, memory);

    for (section, next_rva) in sections_by_rva(model) {
        let source_offset = section.virtual_address().get() as usize;
        let declared_length =
            (section.held_size() as usize).max(directory_reach(section, &directories));
        let until_next = next_rva
            .unwrap_or(memory.len())
            .saturating_sub(source_offset);
        let available = memory.len().saturating_sub(source_offset);
        let source_length = declared_length.min(until_next).min(available);
        let source_end = source_offset.saturating_add(source_length);
        let holds_import_table = import_tables
            .iter()
            .any(|table| table.start < source_end && table.end > source_offset); // empty iat slots need file data
        let empty = !low_alignment
            && section_is_zero(memory, source_offset, source_length)
            && !holds_import_table;
        let raw_size = if source_length == 0 || empty {
            0
        } else {
            align_up(source_length, model.file_alignment as usize)?
        };

        let placed = match (raw_size, low_alignment) {
            (0, _) => 0,
            (_, true) => source_offset,
            (_, false) => raw_offset,
        };
        layouts.push(SectionLayout {
            model: section,
            source_length,
            raw_offset: placed,
            raw_size,
        });

        raw_offset = raw_offset
            .checked_add(raw_size)
            .ok_or_else(|| AppError::new("rebuilt section layout overflowed"))?;
    }

    Ok(layouts)
}

pub(super) fn directory_ranges(model: &PeModel, memory: &[u8]) -> Vec<Range<usize>> {
    (0..model.directory_count)
        .filter(|index| *index != SECURITY_DIRECTORY) // a file offset, not an rva
        .filter_map(|index| model.directory(memory, index))
        .map(|directory| {
            let start = directory.rva().as_usize();
            start..start.saturating_add(directory.size() as usize)
        })
        .collect()
}

pub(super) fn directory_reach(section: &SectionModel, directories: &[Range<usize>]) -> usize {
    let start = section.virtual_address().as_usize();
    let extent = section.span() as usize;

    directories
        .iter()
        .filter(|directory| (start..start.saturating_add(extent)).contains(&directory.start))
        .map(|directory| directory.end.saturating_sub(start).min(extent))
        .max()
        .unwrap_or(0)
}
