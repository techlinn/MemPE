use std::ops::Range;

use iced_x86::{Decoder, DecoderOptions, InstructionInfoFactory, OpAccess, Register};

use super::exception_directory::runtime_functions;
use crate::pe::bytes::{read_u16, read_u32, write_u16, write_u32};
use crate::pe::parse::parse_memory_image;
use crate::pe::{
    BOUND_IMPORT_DIRECTORY, IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_MEM_DISCARDABLE, IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, MAX_IMAGE_SIZE, PeKind, PeModel,
    SECTION_CHARACTERISTICS_OFFSET, SECTION_COUNT_OFFSET, SECTION_HEADER_SIZE,
    SECTION_RAW_POINTER_OFFSET, SECTION_RAW_SIZE_OFFSET, SECTION_RVA_OFFSET,
    SECTION_VIRTUAL_SIZE_OFFSET, SectionModel,
};
use crate::unpack::x86::branches::direct_branches;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum SectionKind {
    Code,
    WritableCode,
    ReadOnly,
    Resources,
    Data,
    Uninitialized,
    Relocations,
}

impl SectionKind {
    pub(crate) const fn characteristics(self) -> u32 {
        const CODE: u32 = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
        const DATA: u32 = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;

        match self {
            Self::Code => CODE,
            Self::WritableCode => CODE | IMAGE_SCN_MEM_WRITE,
            Self::ReadOnly | Self::Resources => DATA,
            Self::Data => DATA | IMAGE_SCN_MEM_WRITE,
            Self::Uninitialized => IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_UNINITIALIZED_DATA,
            Self::Relocations => DATA | IMAGE_SCN_MEM_DISCARDABLE,
        }
    }
}

const LINKER_SECTIONS: [(&[u8], SectionKind); 12] = [
    (b".text", SectionKind::Code),
    (b"CODE", SectionKind::Code),
    (b".rdata", SectionKind::ReadOnly),
    (b".edata", SectionKind::ReadOnly),
    (b".pdata", SectionKind::ReadOnly),
    (b".data", SectionKind::Data),
    (b"DATA", SectionKind::Data),
    (b".idata", SectionKind::Data),
    (b".didat", SectionKind::Data),
    (b".fptable", SectionKind::Data),
    (b".rsrc", SectionKind::Resources),
    (b".reloc", SectionKind::Relocations),
];

pub(super) fn linker_section_kind(name: &[u8]) -> Option<SectionKind> {
    LINKER_SECTIONS
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, kind)| *kind)
}

pub(crate) fn flags_from_names(restored: &mut [u8], end: usize) -> Option<()> {
    let image = parse_memory_image(restored).ok()?;
    let flags = image
        .model()
        .sections
        .iter()
        .filter(|section| section.virtual_address().as_usize() < end)
        .map(|section| {
            let name = section.name();
            let name = &name[..name
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(name.len())];
            let kind = linker_section_kind(name)?;
            Some((section.header_offset, kind.characteristics()))
        })
        .collect::<Option<Vec<_>>>()?; // one name a linker does not give by itself and none is trusted

    for (header, characteristics) in flags {
        write_u32(
            restored,
            header + SECTION_CHARACTERISTICS_OFFSET,
            characteristics,
        )
        .ok()?;
    }
    Some(())
}

pub(crate) struct PlannedSection {
    pub(crate) name: [u8; 8],
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) kind: SectionKind,
}

// memory image: raw data sits at the rva
fn section_header(
    name: &[u8; 8],
    rva: usize,
    size: usize,
    kind: SectionKind,
) -> Option<[u8; SECTION_HEADER_SIZE]> {
    let mut header = [0u8; SECTION_HEADER_SIZE];
    header[..name.len()].copy_from_slice(name);

    let (rva, size) = (u32::try_from(rva).ok()?, u32::try_from(size).ok()?);
    for (offset, value) in [
        (SECTION_VIRTUAL_SIZE_OFFSET, size),
        (SECTION_RVA_OFFSET, rva),
        (SECTION_RAW_SIZE_OFFSET, size),
        (SECTION_RAW_POINTER_OFFSET, rva),
        (SECTION_CHARACTERISTICS_OFFSET, kind.characteristics()),
    ] {
        write_u32(&mut header, offset, value).ok()?;
    }

    Some(header)
}

pub(crate) fn replace_first_section(
    restored: &mut [u8],
    model: &PeModel,
    pieces: &[PlannedSection],
) -> Option<()> {
    let mut table = Vec::new();
    for piece in pieces {
        let size = piece.end.checked_sub(piece.start)?;
        table.extend_from_slice(&section_header(&piece.name, piece.start, size, piece.kind)?);
    }

    let packed = model.sections.first()?;
    let start = packed.virtual_address().as_usize();
    let first = packed.header_offset;
    let rest = model
        .sections
        .len()
        .checked_sub(1)?
        .checked_mul(SECTION_HEADER_SIZE)?;
    let old_end = first.checked_add(SECTION_HEADER_SIZE)?.checked_add(rest)?;
    let new_end = first.checked_add(table.len())?.checked_add(rest)?;

    let headers_end = read_u32(restored, model.size_of_headers_offset).ok()? as usize;
    let past_headers = restored.get(headers_end.max(old_end)..new_end.max(headers_end));
    (new_end <= start && past_headers.is_some_and(|tail| tail.iter().all(|byte| *byte == 0)))
        .then_some(())?;
    free_header_slot(restored, model, old_end..new_end.max(old_end))?;

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

// code_proven: the linker's code size covers every code section, so none lies past it
pub(crate) fn name_sections(
    mut starts: Vec<usize>,
    end: usize,
    hints: &SectionHints,
    code_proven: bool,
) -> Vec<PlannedSection> {
    let unknown = match code_proven {
        true => SectionKind::Data,
        false => SectionKind::WritableCode, // nothing says what it holds: the superset
    };

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
            let (name, kind) = if code {
                (*b".text\0\0\0", SectionKind::Code)
            } else if hints.relocations == Some(start) {
                (*b".reloc\0\0", SectionKind::Relocations)
            } else if inside(hints.resources) {
                (*b".rsrc\0\0\0", SectionKind::Resources)
            } else if hints.constants == Some(start) {
                (*b".rdata\0\0", SectionKind::ReadOnly)
            } else {
                (*b".data\0\0\0", unknown)
            };

            PlannedSection {
                name,
                start,
                end: piece_end,
                kind,
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
    let first = model.sections.first()?;
    let start = first.virtual_address().as_usize();
    Some(start..start.checked_add(first.span() as usize)?)
}

pub(crate) fn header_code_range(restored: &[u8], model: &PeModel) -> Option<Range<usize>> {
    let start = read_u32(restored, model.base_of_code_offset).ok()? as usize;
    let size = read_u32(restored, model.size_of_code_offset).ok()? as usize;
    let end = start
        .checked_add(size)?
        .checked_next_multiple_of(model.section_alignment as usize)?;

    Some(start..end)
}

pub(crate) fn linker_bounds(restored: &[u8], model: &PeModel, code: usize) -> Option<LinkerBounds> {
    let Range { start, end } = first_section_range(model)?;
    let alignment = model.section_alignment as usize;

    let Range {
        start: code_start,
        end: code_end,
    } = header_code_range(restored, model)?; // mpress and fsg keep these

    let fits = code_start == start
        && code_end > start
        && code_end < end
        && (start..code_end).contains(&code);
    fits.then_some(())?;

    let base_of_data = (model.kind == PeKind::Pe32)
        .then(|| read_u32(restored, model.base_of_code_offset.checked_add(4)?).ok())
        .flatten()
        .map(|rva| rva as usize);
    let plausible = |rva: &usize| rva.is_multiple_of(alignment) && (start..end).contains(rva);
    let data = base_of_data
        .filter(plausible)
        .filter(|rva| (code_end..end).contains(rva));

    let all_code_covered = match model.kind {
        PeKind::Pe32 => {
            data == Some(code_end) || !code_reaches_past(restored, model, start..code_end, end) // go's base of data is .data, fsg keeps its own value
        }
        PeKind::Pe32Plus => {
            let functions = runtime_functions(restored, model);
            !functions.is_empty()
                && functions
                    .iter()
                    .all(|function| (start..code_end).contains(&function.begin))
        }
    };
    all_code_covered.then_some(())?; // sizes of several code sections add up short of the last one's end

    Some(LinkerBounds { code_end, data })
}

// a direct store of the program's code: an absolute or rip-relative address it writes in range
pub(crate) fn code_stores_into(
    image: &[u8],
    base: usize,
    bits: u32,
    code: &Range<usize>,
    range: &Range<usize>,
) -> bool {
    let Some(bytes) = image.get(code.clone()) else {
        return true;
    };
    let mut info = InstructionInfoFactory::new();
    let decoder = Decoder::with_ip(
        bits,
        bytes,
        (base + code.start) as u64,
        DecoderOptions::NONE,
    );

    decoder.into_iter().any(|insn| {
        info.info(&insn).used_memory().iter().any(|memory| {
            let fixed = matches!(
                memory.base(),
                Register::None | Register::RIP | Register::EIP
            ) && memory.index() == Register::None;
            let written = matches!(
                memory.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            );
            let at = usize::try_from(memory.displacement())
                .ok()
                .and_then(|at| at.checked_sub(base));
            fixed && written && at.is_some_and(|at| range.contains(&at))
        })
    })
}

// a second code section after the first would be called or jumped to from it
fn code_reaches_past(restored: &[u8], model: &PeModel, code: Range<usize>, end: usize) -> bool {
    let bits = model.kind.bits();
    let past = code.end..end;
    direct_branches(restored, 0, bits, &[code], &|_| None)
        .iter()
        .any(|branch| past.contains(&branch.target))
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

    let mut pieces = name_sections(starts, end, &hints, true);
    if end < packed_end {
        pieces.push(PlannedSection {
            name: [0; 8],
            start: end,
            end: packed_end,
            kind: SectionKind::WritableCode,
        });
    }

    replace_first_section(restored, model, &pieces)
}

pub(crate) fn shed(restored: &mut [u8], model: &PeModel, unused: &[Range<usize>]) -> usize {
    let mut dropped = 0;

    for section in &model.sections {
        let start = section.virtual_address().as_usize();
        if !unused.iter().any(|range| range.start == start) {
            continue;
        }

        let end = start
            .saturating_add(section.span() as usize)
            .min(restored.len());
        let Some(area) = restored.get_mut(start..end) else {
            continue;
        };
        dropped += area.len();
        area.fill(0);

        let _ = write_u32(
            restored,
            section.header_offset + SECTION_CHARACTERISTICS_OFFSET,
            SectionKind::Uninitialized.characteristics(),
        );
    }

    dropped
}

pub(crate) fn next_section_rva(restored: &[u8], model: &PeModel) -> Option<usize> {
    let image_size = read_u32(restored, model.size_of_image_offset).ok()? as usize;
    Some(
        image_size
            .max(restored.len())
            .next_multiple_of(model.section_alignment as usize),
    )
}

pub(crate) fn append(
    restored: &mut Vec<u8>,
    model: &PeModel,
    name: &[u8; 8],
    kind: SectionKind,
    contents: &[u8],
) -> Option<usize> {
    let rva = next_section_rva(restored, model)?;
    let image_end = rva.checked_add(
        contents
            .len()
            .next_multiple_of(model.section_alignment as usize),
    )?;
    (image_end <= MAX_IMAGE_SIZE).then_some(())?;

    let count_at = model.nt_offset.checked_add(SECTION_COUNT_OFFSET)?;
    let count = read_u16(restored, count_at).ok()?;
    let first = model
        .sections
        .iter()
        .map(|section| section.header_offset)
        .min()?;
    let header = first.checked_add(usize::from(count) * SECTION_HEADER_SIZE)?;
    let headers_end = read_u32(restored, model.size_of_headers_offset).ok()? as usize;
    (header.checked_add(SECTION_HEADER_SIZE)? <= headers_end).then_some(())?;

    let fields = section_header(name, rva, contents.len(), kind)?;
    free_header_slot(restored, model, header..header + SECTION_HEADER_SIZE)?;
    restored
        .get_mut(header..header + SECTION_HEADER_SIZE)?
        .copy_from_slice(&fields);
    write_u16(restored, count_at, count.checked_add(1)?).ok()?;
    write_u32(
        restored,
        model.size_of_image_offset,
        u32::try_from(image_end).ok()?,
    )
    .ok()?;

    restored.resize(image_end, 0);
    restored
        .get_mut(rva..rva + contents.len())?
        .copy_from_slice(contents);
    Some(rva)
}

pub(crate) fn cut_tail(restored: &mut Vec<u8>, model: &PeModel, from: usize) -> Option<usize> {
    let mut order: Vec<&SectionModel> = model.sections.iter().collect();
    order.sort_unstable_by_key(|section| section.header_offset);
    let kept = order
        .iter()
        .take_while(|section| section.virtual_address().as_usize() < from)
        .count();
    let tail = order.get(kept..)?;
    if tail.is_empty()
        || tail
            .iter()
            .any(|section| section.virtual_address().as_usize() < from)
    {
        return None;
    }

    let count_at = model.nt_offset.checked_add(SECTION_COUNT_OFFSET)?;
    let listed_now = usize::from(read_u16(restored, count_at).ok()?);
    (listed_now == order.len()).then_some(())?;

    let image_end = from.checked_next_multiple_of(model.section_alignment as usize)?;
    let dropped = restored.len().saturating_sub(image_end);
    for section in tail {
        restored
            .get_mut(section.header_offset..section.header_offset + SECTION_HEADER_SIZE)?
            .fill(0);
    }

    write_u16(restored, count_at, u16::try_from(kept).ok()?).ok()?;
    write_u32(
        restored,
        model.size_of_image_offset,
        u32::try_from(image_end).ok()?,
    )
    .ok()?;
    restored.truncate(image_end);
    Some(dropped)
}

// linkers zero-fill the headers past the section table, so anything else there is the packer's
pub(crate) fn clear_header_slack(restored: &mut [u8]) -> bool {
    let Ok(image) = parse_memory_image(restored) else {
        return false;
    };
    let model = image.model();

    let Some(slack) = header_slack(restored, model) else {
        return false;
    };
    if model.header_bytes_in_use(restored, &slack, None) {
        return false;
    }

    match restored.get_mut(slack) {
        Some(bytes) if bytes.iter().any(|byte| *byte != 0) => {
            bytes.fill(0);
            true
        }
        _ => false,
    }
}

fn header_slack(restored: &[u8], model: &PeModel) -> Option<Range<usize>> {
    let table_end = model
        .sections
        .first()?
        .header_offset
        .checked_add(model.sections.len().checked_mul(SECTION_HEADER_SIZE)?)?;
    let headers_end = read_u32(restored, model.size_of_headers_offset).ok()? as usize;
    let first_section = model.sections.first()?.virtual_address().as_usize();

    let end = headers_end.min(first_section);
    (table_end < end).then_some(table_end..end)
}

fn free_header_slot(restored: &mut [u8], model: &PeModel, slot: Range<usize>) -> Option<()> {
    (!model.header_bytes_in_use(restored, &slot, Some(BOUND_IMPORT_DIRECTORY))).then_some(())?;

    let bound = model.directory(restored, BOUND_IMPORT_DIRECTORY);
    let stale = bound.is_some_and(|bound| {
        let start = bound.rva().as_usize();
        start < slot.end && slot.start < start.saturating_add(bound.size() as usize)
    });
    if stale {
        model.clear_directory(restored, BOUND_IMPORT_DIRECTORY); // pack time data, stale now
    }

    restored.get_mut(slot)?.fill(0);
    Some(())
}
