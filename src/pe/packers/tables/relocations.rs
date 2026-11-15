use std::ops::Range;

use super::{FIRST_SECTION_RVA, set_directory};
use crate::pe::image::{read_pointer, read_u32, write_u32, write_u64};
use crate::pe::{BASERELOC_DIRECTORY, PeKind, PeModel, RELOCATION_DIR64, RELOCATION_HIGHLOW};

const PAGE_MASK: u32 = 0xFFF;
pub(crate) const RELOCATION_BLOCK_HEADER: usize = 8;
pub(crate) const RELOCATION_BLOCK_SIZE_OFFSET: usize = 4;
pub(crate) const MAX_RELOCATION_BLOCK: usize = 0x10000;
const RELOCATION_KIND_SHIFT: u16 = 12;
const KNOWN_RELOCATION_KINDS: [u16; 5] = [0, 1, 2, 3, 10];
const RELOCATION_OFFSET_MASK: u16 = 0xFFF;
const USED_FIXUP_MAJORITY: usize = 3; // a real table keeps pointers in most fields however long the program ran

pub(crate) fn relocation_blocks(entries: &[(u32, u16)]) -> Option<Vec<u8>> {
    let mut sorted = entries.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    let mut blocks = Vec::new();
    for page in sorted.chunk_by(|(left, _), (right, _)| left & !PAGE_MASK == right & !PAGE_MASK) {
        let mut words = page
            .iter()
            .map(|(rva, kind)| (kind << RELOCATION_KIND_SHIFT) | (rva & PAGE_MASK) as u16)
            .collect::<Vec<_>>();
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
        let Ok(block_size) = read_u32(table, cursor.saturating_add(RELOCATION_BLOCK_SIZE_OFFSET))
        else {
            return false;
        };

        let block_size = block_size as usize;

        if block_size == 0 && read_u32(table, cursor).is_ok_and(|page| page == 0) {
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

        let known = words.as_chunks::<2>().0.iter().all(|word| {
            KNOWN_RELOCATION_KINDS.contains(&(u16::from_le_bytes(*word) >> RELOCATION_KIND_SHIFT))
        });

        if !known {
            return false;
        }

        cursor = cursor.saturating_add(block_size);
    }

    true
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fixups {
    Pristine, // nothing ran since the fixups were applied, so every field still holds a pointer
    Used,     // the program ran, and has since stored other things in some of the fields
}

pub(crate) fn find_relocation_table(
    original: &[u8],
    image: &Range<usize>,
    base: usize,
    page: usize,
    fixups: Fixups,
) -> Option<Range<usize>> {
    (image.start..image.end)
        .step_by(page.max(1))
        .find_map(|start| relocation_table_at(original, start, image, base, fixups))
}

pub(crate) fn restore_relocation_directory(
    restored: &mut [u8],
    model: &PeModel,
    base: usize,
    end: usize,
) -> Option<usize> {
    let declared = model
        .directory(restored, BASERELOC_DIRECTORY)
        .ok()
        .flatten()
        .map(|directory| directory.rva().as_usize());
    if declared.is_some_and(|rva| rva < end) {
        return None; // still the program's own
    }

    let image = FIRST_SECTION_RVA..end;
    let page = model.section_alignment as usize;
    let table = find_relocation_table(restored, &image, base, page, Fixups::Used)?; // the packer applied them itself and points the header at a table of its own

    set_directory(
        restored,
        model,
        BASERELOC_DIRECTORY,
        table.start,
        table.len(),
    )?;
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
        let page = read_u32(original, cursor).ok()? as usize;
        let size =
            read_u32(original, cursor.checked_add(RELOCATION_BLOCK_SIZE_OFFSET)?).ok()? as usize;
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
        for word in words.as_chunks::<2>().0 {
            let word = u16::from_le_bytes(*word);
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
                        continue; // packers blank some directories, like mew does the tls one
                    }

                    let points_inside = value
                        .checked_sub(base)
                        .is_some_and(|target| target <= image.end);
                    match (points_inside, state) {
                        (true, _) => fixups += 1,
                        (false, Fixups::Used) => overwritten += 1,
                        (false, Fixups::Pristine) => return None, // the packer never ran these, so they still hold link time pointers
                    }
                }
                _ => return None,
            }
        }

        cursor = cursor.checked_add(size)?;
        (cursor < image.end).then_some(())?;
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
    let directory = model.directory(restored, BASERELOC_DIRECTORY).ok()??;
    let start = directory.rva().as_usize();
    let table = restored.get(start..start.checked_add(directory.size() as usize)?)?;

    let mut fields = Vec::new();
    let mut cursor = 0usize;
    while cursor + RELOCATION_BLOCK_HEADER <= table.len() {
        let page = read_u32(table, cursor).ok()? as usize;
        let size = read_u32(table, cursor + RELOCATION_BLOCK_SIZE_OFFSET).ok()? as usize;
        if page == 0 || size < RELOCATION_BLOCK_HEADER {
            break;
        }

        let words = table.get(cursor + RELOCATION_BLOCK_HEADER..cursor.checked_add(size)?)?;
        for word in words.as_chunks::<2>().0 {
            let word = u16::from_le_bytes(*word);
            let kind = match word >> RELOCATION_KIND_SHIFT {
                RELOCATION_HIGHLOW => PeKind::Pe32,
                RELOCATION_DIR64 => PeKind::Pe32Plus,
                _ => continue,
            };
            fields.push((page + usize::from(word & RELOCATION_OFFSET_MASK), kind));
        }

        cursor += size;
    }

    Some(fields)
}

pub(crate) fn drop_relocation_blocks(
    restored: &mut [u8],
    model: &PeModel,
    sections: &[Range<usize>],
) -> Option<(usize, usize)> {
    let entry = model.directory_offset(BASERELOC_DIRECTORY).ok()??;
    let rva = read_u32(restored, entry).ok()? as usize;
    let size = read_u32(restored, entry + 4).ok()? as usize;
    let table = restored.get(rva..rva.checked_add(size)?)?.to_vec();

    let mut kept: Vec<u8> = Vec::with_capacity(table.len());
    let mut dropped = 0;
    let mut blocks = 0;
    let mut at = 0;
    while at + RELOCATION_BLOCK_HEADER <= table.len() {
        let page = read_u32(&table, at).ok()? as usize;
        let length = read_u32(&table, at + 4).ok()? as usize;
        if length < RELOCATION_BLOCK_HEADER || at.checked_add(length)? > table.len() {
            break; // a malformed tail is left where it is for the rebuild to judge
        }

        match sections.iter().any(|section| section.contains(&page)) {
            true => dropped += 1,
            false => {
                blocks += 1;
                kept.extend_from_slice(&table[at..at + length]);
            }
        }
        at += length;
    }

    let area = restored.get_mut(rva..rva + size)?;
    area.fill(0);
    area[..kept.len()].copy_from_slice(&kept);

    match kept.is_empty() {
        true => {
            write_u32(restored, entry, 0).ok()?;
            write_u32(restored, entry + 4, 0).ok()?;
        }
        false => write_u32(restored, entry + 4, u32::try_from(kept.len()).ok()?).ok()?,
    }
    Some((dropped, blocks))
}
