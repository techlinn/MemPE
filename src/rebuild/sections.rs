use std::collections::HashSet;

use super::SectionLayout;
use crate::pe::bytes::write_u32;
use crate::pe::{
    SECTION_NAME_SIZE, SECTION_RAW_POINTER_OFFSET, SECTION_RAW_SIZE_OFFSET,
    SECTION_VIRTUAL_SIZE_OFFSET,
};
use crate::{AppError, AppResult};

const PRINTABLE_FIRST: u8 = 0x20;
const PRINTABLE_LAST: u8 = 0x7e;

#[derive(Default)]
pub(super) struct SectionNames {
    pub(super) renamed: usize,
    pub(super) named: usize,
    pub(super) unreplaced: usize,
}

enum NameFault {
    Empty,
    Unreadable,
}

pub(super) fn write_sections(
    output: &mut [u8],
    memory: &[u8],
    layouts: &[SectionLayout<'_>],
) -> AppResult<SectionNames> {
    let mut taken = layouts
        .iter()
        .map(|layout| *layout.model.name())
        .collect::<HashSet<_>>();
    let mut names = SectionNames::default();

    for (index, layout) in layouts.iter().enumerate() {
        let header = layout.model.header_offset;

        if let Some(fault) = name_fault(layout.model.name()) {
            match unique_replacement_name(index, layouts.len(), &taken) {
                Some(name) => {
                    output
                        .get_mut(header..header.saturating_add(SECTION_NAME_SIZE))
                        .ok_or_else(|| AppError::new("section name lies outside the rebuilt PE"))?
                        .copy_from_slice(&name);
                    taken.insert(name);
                    names.count(&fault);
                }
                None => names.unreplaced = names.unreplaced.saturating_add(1),
            }
        }

        if layout.model.virtual_size == 0 {
            write_u32(
                output,
                header.saturating_add(SECTION_VIRTUAL_SIZE_OFFSET),
                layout.model.mapped_size(),
            )?; // zero VirtualSize means raw size
        }

        write_u32(
            output,
            header.saturating_add(SECTION_RAW_SIZE_OFFSET),
            u32::try_from(layout.raw_size)
                .map_err(|_| AppError::new("section raw size does not fit a PE field"))?,
        )?;
        write_u32(
            output,
            header.saturating_add(SECTION_RAW_POINTER_OFFSET),
            u32::try_from(layout.raw_offset)
                .map_err(|_| AppError::new("section file offset does not fit a PE field"))?,
        )?;

        if layout.raw_size == 0 {
            continue;
        }

        let source_offset = layout.model.virtual_address().get() as usize;
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

    Ok(names)
}

impl SectionNames {
    fn count(&mut self, fault: &NameFault) {
        let counter = match fault {
            NameFault::Empty => &mut self.named,
            NameFault::Unreadable => &mut self.renamed,
        };
        *counter = counter.saturating_add(1);
    }
}

pub(super) fn section_is_zero(memory: &[u8], offset: usize, length: usize) -> bool {
    memory
        .get(offset..offset.saturating_add(length))
        .is_some_and(|slice| slice.iter().all(|byte| *byte == 0))
}

fn unique_replacement_name(
    index: usize,
    count: usize,
    taken: &HashSet<[u8; 8]>,
) -> Option<[u8; 8]> {
    let mut position = index.saturating_add(1);

    // one more candidate than names taken
    for _attempt in 0..=taken.len() {
        let candidate = replacement_name(position)?;

        if !taken.contains(&candidate) {
            return Some(candidate);
        }

        position = position.checked_add(count.max(1))?;
    }

    None
}

fn name_fault(name: &[u8; 8]) -> Option<NameFault> {
    let end = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name.len());
    let label = name.get(..end).unwrap_or(name);

    if label.is_empty() {
        return Some(NameFault::Empty);
    }

    let readable = label
        .iter()
        .all(|byte| (PRINTABLE_FIRST..=PRINTABLE_LAST).contains(byte))
        && label.iter().any(|byte| *byte != b' ');

    (!readable).then_some(NameFault::Unreadable)
}

fn replacement_name(position: usize) -> Option<[u8; 8]> {
    let text = format!(".sec{position:02}");
    let bytes = text.as_bytes();
    let mut replacement = [0u8; SECTION_NAME_SIZE];
    replacement.get_mut(..bytes.len())?.copy_from_slice(bytes);

    Some(replacement)
}
