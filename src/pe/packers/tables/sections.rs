use std::ops::Range;

use crate::pe::image::{read_u32, write_u16, write_u32};
use crate::pe::{PeKind, PeModel, SECTION_HEADER_SIZE};

pub(crate) const SECTION_COUNT_OFFSET: usize = 6; // from the nt signature
pub(crate) const SECTION_RVA_OFFSET: usize = 12;
pub(crate) const SECTION_CHARACTERISTICS_OFFSET: usize = 36;
const SECTION_VIRTUAL_SIZE_OFFSET: usize = 8;
const SECTION_RAW_SIZE_OFFSET: usize = 16;
const SECTION_RAW_POINTER_OFFSET: usize = 20;
pub(crate) const CODE_SECTION: u32 = 0x6000_0020; // read, execute, code
pub(crate) const DATA_SECTION: u32 = 0xC000_0040; // read, write, initialized data
pub(super) const RESOURCE_SECTION: u32 = 0x4000_0040; // read, initialized data
pub(super) const READ_ONLY_SECTION: u32 = 0x4000_0040;
pub(super) const RELOCATION_SECTION: u32 = 0x4200_0040; // read, discardable, initialized data

pub(crate) struct SectionPiece {
    pub(crate) name: [u8; 8],
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) characteristics: u32,
}

pub(crate) fn replace_first_section(
    restored: &mut [u8],
    model: &PeModel,
    pieces: &[SectionPiece],
) -> Option<()> {
    let mut table = Vec::new();
    for piece in pieces {
        let mut header = [0u8; SECTION_HEADER_SIZE];
        header[..piece.name.len()].copy_from_slice(&piece.name);

        let size = u32::try_from(piece.end.checked_sub(piece.start)?).ok()?;
        let rva = u32::try_from(piece.start).ok()?;
        for (offset, value) in [
            (SECTION_VIRTUAL_SIZE_OFFSET, size),
            (SECTION_RVA_OFFSET, rva),
            (SECTION_RAW_SIZE_OFFSET, size),
            (SECTION_RAW_POINTER_OFFSET, rva),
            (SECTION_CHARACTERISTICS_OFFSET, piece.characteristics),
        ] {
            write_u32(&mut header, offset, value).ok()?;
        }

        table.extend_from_slice(&header);
    }

    let packed = model.sections().first()?;
    let start = packed.virtual_address().as_usize();
    let first = packed.header_offset;
    let rest = model
        .sections()
        .len()
        .checked_sub(1)?
        .checked_mul(SECTION_HEADER_SIZE)?;
    let old_end = first.checked_add(SECTION_HEADER_SIZE)?.checked_add(rest)?;
    let new_end = first.checked_add(table.len())?.checked_add(rest)?;

    let headers_end = read_u32(restored, model.size_of_headers_offset).ok()? as usize;
    let grown = restored.get(headers_end.max(old_end)..new_end.max(headers_end));

    (new_end <= start && grown.is_some_and(|tail| tail.iter().all(|byte| *byte == 0)))
        .then_some(())?;

    if new_end > headers_end {
        let headers_end = new_end.checked_next_multiple_of(model.file_alignment as usize)?;
        write_u32(
            restored,
            model.size_of_headers_offset,
            u32::try_from(headers_end).ok()?,
        )
        .ok()?;
    }

    let others = restored
        .get(first.checked_add(SECTION_HEADER_SIZE)?..old_end)?
        .to_vec();
    table.extend_from_slice(&others);
    restored.get_mut(first..new_end)?.copy_from_slice(&table);

    let count = u16::try_from(table.len() / SECTION_HEADER_SIZE).ok()?;
    write_u16(
        restored,
        model.nt_offset.checked_add(SECTION_COUNT_OFFSET)?,
        count,
    )
    .ok()
}

pub(crate) struct SectionHints {
    pub(crate) code: Option<usize>,
    pub(crate) code_end: Option<usize>,
    pub(crate) constants: Option<usize>,
    pub(crate) relocations: Option<usize>,
    pub(crate) resources: Option<usize>,
}

pub(crate) fn name_sections(
    mut starts: Vec<usize>,
    end: usize,
    hints: &SectionHints,
) -> Vec<SectionPiece> {
    starts.sort_unstable();
    starts.dedup();
    starts
        .iter()
        .enumerate()
        .map(|(index, &start)| {
            let piece_end = starts.get(index + 1).copied().unwrap_or(end);
            let inside =
                |rva: Option<usize>| rva.is_some_and(|rva| (start..piece_end).contains(&rva));
            let code =
                inside(hints.code) || hints.code_end.is_some_and(|code_end| start < code_end);
            let (name, characteristics) = if code {
                (*b".text\0\0\0", CODE_SECTION)
            } else if hints.relocations == Some(start) {
                (*b".reloc\0\0", RELOCATION_SECTION)
            } else if inside(hints.resources) {
                (*b".rsrc\0\0\0", RESOURCE_SECTION)
            } else if hints.constants == Some(start) {
                (*b".rdata\0\0", READ_ONLY_SECTION)
            } else {
                (*b".data\0\0\0", DATA_SECTION)
            };

            SectionPiece {
                name,
                start,
                end: piece_end,
                characteristics,
            }
        })
        .collect()
}

#[derive(Clone, Copy)]
pub(crate) struct LinkerBounds {
    pub(crate) code_end: usize,
    pub(crate) data: Option<usize>,
}

pub(crate) fn first_section_range(model: &PeModel) -> Option<Range<usize>> {
    let first = model.sections().first()?;
    let start = first.virtual_address().as_usize();
    Some(start..start.checked_add(first.span() as usize)?)
}

pub(crate) fn linker_bounds(restored: &[u8], model: &PeModel, code: usize) -> Option<LinkerBounds> {
    let Range { start, end } = first_section_range(model)?;
    let alignment = model.section_alignment as usize;

    let code_start = read_u32(restored, model.base_of_code_offset).ok()? as usize; // mpress and fsg keep these
    let code_size = read_u32(restored, model.size_of_code_offset).ok()? as usize;
    let code_end = code_start
        .checked_add(code_size)?
        .checked_next_multiple_of(alignment)?;

    let fits = code_start == start
        && code_end > start
        && code_end < end
        && (start..code_end).contains(&code);
    fits.then_some(())?;

    let data = (model.kind() == PeKind::Pe32)
        .then(|| read_u32(restored, model.base_of_code_offset.checked_add(4)?).ok())
        .flatten()
        .map(|rva| rva as usize)
        .filter(|rva| rva.is_multiple_of(alignment) && (code_end..end).contains(rva));

    Some(LinkerBounds { code_end, data })
}

pub(crate) fn split_merged_section(
    restored: &mut [u8],
    model: &PeModel,
    hints: &SectionHints,
    data: Option<usize>,
    image_end: Option<usize>,
) -> Option<()> {
    let Range {
        start,
        end: packed_end,
    } = first_section_range(model)?;
    let alignment = model.section_alignment as usize;

    let code = hints.code.unwrap_or(start);
    let bounds = linker_bounds(restored, model, code)?;
    let end = image_end
        .filter(|end| {
            end.is_multiple_of(alignment) && (bounds.code_end + 1..packed_end).contains(end)
        })
        .unwrap_or(packed_end);

    let inner = [
        hints.constants,
        bounds.data,
        data,
        hints.relocations,
        hints.resources,
    ]
    .into_iter()
    .flatten()
    .filter(|rva| rva.is_multiple_of(alignment) && (bounds.code_end..end).contains(rva));
    let starts = [start, bounds.code_end].into_iter().chain(inner).collect();

    let hints = SectionHints {
        code: Some(code),
        code_end: Some(bounds.code_end),
        ..*hints
    };

    let mut pieces = name_sections(starts, end, &hints);
    if end < packed_end {
        pieces.push(SectionPiece {
            name: [0; 8],
            start: end,
            end: packed_end,
            characteristics: DATA_SECTION,
        });
    }

    replace_first_section(restored, model, &pieces)
}
