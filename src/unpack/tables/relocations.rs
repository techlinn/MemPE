use std::ops::Range;

use super::{rewrite_table, unique};
use crate::pe::bytes::{read_pointer, relocation_block, relocation_words, write_u32, write_u64};
use crate::pe::{
    BASERELOC_DIRECTORY, PeKind, PeModel, RELOCATION_ABSOLUTE, RELOCATION_BLOCK_HEADER,
    RELOCATION_DIR64, RELOCATION_HIGH, RELOCATION_HIGHLOW, RELOCATION_KIND_SHIFT, RELOCATION_LOW,
    RELOCATION_OFFSET_MASK, first_section_rva,
};

const PAGE_MASK: u32 = RELOCATION_OFFSET_MASK as u32;
pub(crate) const RELOCATION_BLOCK_SIZE_OFFSET: usize = 4;
pub(crate) const MAX_RELOCATION_BLOCK: usize = 0x10000;
const KNOWN_RELOCATION_KINDS: [u16; 5] = [
    RELOCATION_ABSOLUTE,
    RELOCATION_HIGH,
    RELOCATION_LOW,
    RELOCATION_HIGHLOW,
    RELOCATION_DIR64,
];
const USED_FIXUP_MAJORITY: usize = 3; // most fields still pointers

pub(crate) fn relocation_blocks(entries: &[(u32, u16)]) -> Option<Vec<u8>> {
    let mut sorted = entries.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    let mut blocks = Vec::new();
    for page in sorted.chunk_by(|(left, _), (right, _)| left & !PAGE_MASK == right & !PAGE_MASK) {
        let mut words = page
            .iter()
            .map(|(rva, kind)| {
                (*kind <= u16::MAX >> RELOCATION_KIND_SHIFT)
                    .then(|| (kind << RELOCATION_KIND_SHIFT) | (rva & PAGE_MASK) as u16)
            })
            .collect::<Option<Vec<_>>>()?;
        if !words.len().is_multiple_of(2) {
            words.push(0);
        }

        let size = u32::try_from(
            words
                .len()
                .checked_mul(2)?
                .checked_add(RELOCATION_BLOCK_HEADER)?,
        )
        .ok()?;
        blocks.extend_from_slice(&(page.first()?.0 & !PAGE_MASK).to_le_bytes());
        blocks.extend_from_slice(&size.to_le_bytes());

        for word in words {
            blocks.extend_from_slice(&word.to_le_bytes());
        }
    }

    Some(blocks)
}

pub(crate) fn relocations_intact(bytes: &[u8], start: usize, size: usize) -> bool {
    let Some(table) = bytes.get(start..start.saturating_add(size)) else {
        return false;
    };

    if table.iter().all(|byte| *byte == 0) {
        return false;
    }

    let mut cursor = 0usize;
    while cursor < table.len() {
        let Some((page, block_size)) = relocation_block(table, cursor) else {
            return false;
        };

        if block_size == 0 && page == 0 {
            return true;
        }

        if block_size < RELOCATION_BLOCK_HEADER || !block_size.is_multiple_of(2) {
            return false;
        }

        let Some(words) = table
            .get(cursor.saturating_add(RELOCATION_BLOCK_HEADER)..cursor.saturating_add(block_size))
        else {
            return false;
        };

        let known = relocation_words(words)
            .all(|word| KNOWN_RELOCATION_KINDS.contains(&(word >> RELOCATION_KIND_SHIFT)));

        if !known {
            return false;
        }

        cursor = cursor.saturating_add(block_size);
    }

    true
}

#[derive(Clone, Copy)]
pub(crate) enum Fixups {
    Pristine, // untouched since fixups
    Used,     // program overwrote some fields
}

pub(crate) fn find_relocation_table(
    original: &[u8],
    image: &Range<usize>,
    base: usize,
    page: usize,
    fixups: Fixups,
) -> Option<Range<usize>> {
    let mut tables: Vec<Range<usize>> = Vec::new();
    for start in (image.start..image.end).step_by(page.max(1)) {
        if tables.last().is_some_and(|table| start < table.end) {
            continue; // a later block of the table just found
        }
        if let Some(table) = relocation_table_at(original, start, image, base, fixups) {
            tables.push(table);
        }
    }

    unique(tables)
}

pub(crate) fn restore_relocation_directory(
    restored: &mut [u8],
    model: &PeModel,
    base: usize,
    end: usize,
) -> Option<usize> {
    let declared = model
        .directory(restored, BASERELOC_DIRECTORY)
        .map(|directory| directory.rva().as_usize());
    if declared.is_some_and(|rva| rva < end) {
        return None;
    }

    let image = first_section_rva(&model.sections)?..end;
    let page = model.section_alignment as usize;
    let table = find_relocation_table(restored, &image, base, page, Fixups::Used)?; // packer's own fixup table

    model.set_directory(restored, BASERELOC_DIRECTORY, table.start, table.len())?;
    Some(table.start)
}

fn relocation_table_at(
    original: &[u8],
    start: usize,
    image: &Range<usize>,
    base: usize,
    state: Fixups,
) -> Option<Range<usize>> {
    let mut cursor = start;
    let mut fixups = 0usize;
    let mut overwritten = 0usize;

    loop {
        let (page, size) = relocation_block(original, cursor)?;
        if page == 0 && size == 0 {
            break;
        }

        let block = page & PAGE_MASK as usize == 0
            && image.contains(&page)
            && (RELOCATION_BLOCK_HEADER..=MAX_RELOCATION_BLOCK).contains(&size)
            && size.is_multiple_of(2);
        block.then_some(())?;

        let words = original
            .get(cursor.checked_add(RELOCATION_BLOCK_HEADER)?..cursor.checked_add(size)?)?;
        for word in relocation_words(words) {
            match word >> RELOCATION_KIND_SHIFT {
                0 => continue,
                kind @ (RELOCATION_HIGHLOW | RELOCATION_DIR64) => {
                    let width = match kind {
                        RELOCATION_DIR64 => PeKind::Pe32Plus,
                        _ => PeKind::Pe32,
                    };
                    let field = page.checked_add(usize::from(word & RELOCATION_OFFSET_MASK))?;
                    let value = read_pointer(original, field, width).ok()?;
                    if value == 0 {
                        continue; // packers blank some directories
                    }

                    let points_inside = value
                        .checked_sub(base)
                        .is_some_and(|target| target <= image.end);
                    match (points_inside, state) {
                        (true, _) => fixups += 1,
                        (false, Fixups::Used) => overwritten += 1,
                        (false, Fixups::Pristine) => return None, // never ran: still link time pointers
                    }
                }
                _ => return None,
            }
        }

        cursor = cursor.checked_add(size)?;
        if cursor >= image.end {
            (cursor == image.end).then_some(())?; // fills its last page: no terminator
            break;
        }
    }

    (fixups > overwritten.saturating_mul(USED_FIXUP_MAJORITY)).then_some(start..cursor)
}

pub(crate) fn relocate(
    bytes: &mut [u8],
    restored: &[u8],
    model: &PeModel,
    adjust: impl Fn(usize, PeKind) -> usize,
) -> Option<()> {
    for (at, kind) in relocated_fields(restored, model)? {
        let Ok(value) = read_pointer(bytes, at, kind) else {
            continue;
        };

        let moved = adjust(value, kind);
        let _ = match kind {
            PeKind::Pe32 => write_u32(bytes, at, moved as u32),
            PeKind::Pe32Plus => write_u64(bytes, at, moved as u64),
        };
    }

    Some(())
}

pub(crate) fn relocated_fields(restored: &[u8], model: &PeModel) -> Option<Vec<(usize, PeKind)>> {
    let directory = model.directory(restored, BASERELOC_DIRECTORY)?;
    let start = directory.rva().as_usize();
    let table = restored.get(start..start.checked_add(directory.size() as usize)?)?;

    let mut fields = Vec::new();
    for (page, block) in blocks(table) {
        if page == 0 {
            break;
        }
        let block = block?;

        for word in relocation_words(&block[RELOCATION_BLOCK_HEADER..]) {
            let kind = match word >> RELOCATION_KIND_SHIFT {
                RELOCATION_HIGHLOW => PeKind::Pe32,
                RELOCATION_DIR64 => PeKind::Pe32Plus,
                _ => continue,
            };
            fields.push((page + usize::from(word & RELOCATION_OFFSET_MASK), kind));
        }
    }

    Some(fields)
}

fn blocks(table: &[u8]) -> impl Iterator<Item = (usize, Option<&[u8]>)> {
    let mut at = 0usize;
    let mut broken = false;

    std::iter::from_fn(move || {
        let (page, size) = relocation_block(table, at)?;
        if broken || size < RELOCATION_BLOCK_HEADER {
            return None;
        }

        let block = at.checked_add(size).and_then(|end| table.get(at..end));
        broken = block.is_none();
        at = at.saturating_add(size);
        Some((page, block)) // none: claims more than the table holds
    })
}

pub(crate) fn drop_relocation_blocks(
    restored: &mut [u8],
    model: &PeModel,
    sections: &[Range<usize>],
) -> Option<(usize, usize)> {
    let mut dropped = 0;
    let mut kept_blocks = 0;
    rewrite_table(restored, model, BASERELOC_DIRECTORY, |table| {
        let mut kept = Vec::with_capacity(table.len());
        for (page, block) in blocks(table) {
            let Some(block) = block else {
                break;
            };
            match sections.iter().any(|section| section.contains(&page)) {
                true => dropped += 1,
                false => {
                    kept_blocks += 1;
                    kept.extend_from_slice(block);
                }
            }
        }
        kept
    })?;

    Some((dropped, kept_blocks))
}
