use crate::pe::image::{read_pointer, read_u32, write_u32, write_u64};
use crate::pe::{BASERELOC_DIRECTORY, PeKind, PeModel, RELOCATION_DIR64, RELOCATION_HIGHLOW};

const PAGE_MASK: u32 = 0xFFF;
pub(crate) const RELOCATION_BLOCK_HEADER: usize = 8;
pub(crate) const RELOCATION_BLOCK_SIZE_OFFSET: usize = 4;
pub(crate) const MAX_RELOCATION_BLOCK: usize = 0x10000;
const RELOCATION_KIND_SHIFT: u16 = 12;
const KNOWN_RELOCATION_KINDS: [u16; 5] = [0, 1, 2, 3, 10];
const RELOCATION_OFFSET_MASK: u16 = 0xFFF;

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
