use std::ops::Range;

use super::debug_directory::debug_entries;
use super::exception_directory::runtime_functions;
use super::relocations::relocations_intact;
use super::sections::{PlannedSection, SectionKind, linker_section_kind};
use super::{SCAN_STEP, unique};
use crate::pe::bytes::read_u32;
use crate::pe::{BASERELOC_DIRECTORY, PeModel, first_section_rva};
use crate::pe::{DEBUG_ADDRESS_OFFSET, DEBUG_SIZE_OFFSET, DEBUG_TYPE_OFFSET};

pub(super) const DEBUG_TYPE_POGO: u32 = 13;
const POGO_SIGNATURES: [&[u8]; 5] = [b"\0\0\0\0", b"\0UGP", b"\0IGP", b"\0OGP", b"GCTL"]; // none, PGU, PGI, PGO and LTCG
const POGO_RECORDS: usize = 4;
const POGO_FIRST_NAME: usize = 12;
const POGO_RECORD_HEADER: usize = 8;
const MAX_POGO_NAME: usize = 64;
const MAX_POGO_PARTS: usize = 4_096;
const MIN_POGO_PARTS: usize = 3;
const TLS_PART: &[u8] = b".rdata$T"; // msvc's _tls_used
const CODE_PART: &[u8] = b".text";
const READ_ONLY_PARTS: [&[u8]; 7] = [
    b".rdata", b".idata", b".CRT", b".00cfg", b".rtc", b".xdata", b".edata",
];
const WRITABLE_PARTS: [&[u8]; 2] = [b".data", b".bss"];
const SECTION_NAMES: [&[u8]; 3] = [CODE_PART, b".rdata", b".data"];

pub(crate) struct CoffGroup {
    pub(crate) rva: usize,
    pub(crate) size: usize,
    pub(crate) name: Vec<u8>,
}

pub(crate) fn pogo_parts(bytes: &[u8], model: &PeModel, end: usize) -> Option<Vec<CoffGroup>> {
    let first = first_section_rva(&model.sections)?;
    let image = first..end;
    let listed = debug_entries(bytes, model).find_map(|entry| {
        (read_u32(bytes, entry.checked_add(DEBUG_TYPE_OFFSET)?).ok()? == DEBUG_TYPE_POGO)
            .then_some(())?;
        let rva = read_u32(bytes, entry.checked_add(DEBUG_ADDRESS_OFFSET)?).ok()? as usize;
        let size = read_u32(bytes, entry.checked_add(DEBUG_SIZE_OFFSET)?).ok()? as usize;
        Some(rva..rva.checked_add(size)?)
    });

    let found = listed.or_else(|| {
        unique(
            image
                .clone()
                .step_by(SCAN_STEP)
                .filter(|at| {
                    pogo_data(bytes, *at, &image)
                        && read_u32(bytes, at + POGO_RECORDS).map(|rva| rva as usize) == Ok(first)
                })
                .map(|at| at..end),
        )
    })?;

    let mut parts: Vec<CoffGroup> = Vec::new();
    let mut at = found.start.checked_add(POGO_RECORDS)?;
    while parts.len() < MAX_POGO_PARTS {
        let Some((part, next)) =
            pogo_record(bytes, at, found.end.min(bytes.len()), end, parts.last())
        else {
            break;
        };
        parts.push(part);
        at = next;
    }

    (parts.len() >= MIN_POGO_PARTS).then_some(parts)
}

fn pogo_record(
    bytes: &[u8],
    at: usize,
    records_end: usize,
    image_end: usize,
    previous: Option<&CoffGroup>,
) -> Option<(CoffGroup, usize)> {
    (at.checked_add(POGO_RECORD_HEADER)? < records_end).then_some(())?;

    let rva = read_u32(bytes, at).ok()? as usize;
    let size = read_u32(bytes, at.checked_add(4)?).ok()? as usize;
    let name_start = at.checked_add(POGO_RECORD_HEADER)?;
    let text = bytes.get(name_start..name_start.saturating_add(MAX_POGO_NAME).min(bytes.len()))?;
    let name = text.get(..text.iter().position(|byte| *byte == 0)?)?;

    let sound = (name.first() == Some(&b'.') || previous.is_some()) // later parts may be named like _RDATA
        && !name.is_empty()
        && name.iter().all(u8::is_ascii_graphic)
        && rva.checked_add(size).is_some_and(|stop| stop <= image_end)
        && previous.is_none_or(|last| last.rva <= rva);
    sound.then_some(())?;

    let next = name_start
        .checked_add(name.len() + 1)?
        .checked_next_multiple_of(4)?;

    let part = CoffGroup {
        rva,
        size,
        name: name.to_vec(),
    };
    Some((part, next))
}

// merged groups take on the characteristics of the standard section they merge into
fn named_kind(names: &[Vec<u8>]) -> Option<SectionKind> {
    let first = names.first()?;
    let alone = names.iter().all(|name| name == first);
    if let Some(kind) = linker_section_kind(first).filter(|_| alone) {
        return Some(kind);
    }

    let holds = |wanted: &[&[u8]]| names.iter().any(|name| wanted.contains(&name.as_slice()));
    let (code, data, constants) = (
        holds(&[CODE_PART]),
        holds(&WRITABLE_PARTS),
        holds(&[b".rdata"]),
    );
    match (code, data, constants) {
        (true, true, _) => Some(SectionKind::WritableCode),
        (true, false, _) => Some(SectionKind::Code),
        (false, true, _) => Some(SectionKind::Data),
        (false, false, true) => Some(SectionKind::ReadOnly),
        (false, false, false) => names
            .iter()
            .all(|name| READ_ONLY_PARTS.contains(&name.as_slice()))
            .then_some(SectionKind::ReadOnly),
    }
}

// tls callbacks are left out: a packer module may have placed that directory by inference
fn code_addresses(restored: &[u8], model: &PeModel, entry: Option<usize>) -> Vec<usize> {
    let unwound = runtime_functions(restored, model)
        .into_iter()
        .map(|function| function.begin);

    entry.into_iter().chain(unwound).collect()
}

pub(crate) fn pogo_sections(
    parts: &[CoffGroup],
    restored: &[u8],
    model: &PeModel,
    end: usize,
    entry: Option<usize>,
) -> Option<Vec<PlannedSection>> {
    let alignment = model.section_alignment as usize;
    let first = model.sections.first()?.virtual_address().as_usize();

    let prefix = |name: &[u8]| -> Vec<u8> {
        name.split(|byte| *byte == b'$')
            .next()
            .unwrap_or(name)
            .to_vec()
    };

    let mut sections: Vec<(usize, usize, Vec<Vec<u8>>)> = Vec::new(); // start, end of its parts, part names
    for part in parts.iter().filter(|part| part.rva < end) {
        let stop = part.rva.checked_add(part.size)?.min(end);
        let name = prefix(&part.name);
        let opens = sections.last().is_none_or(|(_, last_end, _)| {
            part.rva.is_multiple_of(alignment) && part.rva > *last_end // flush against the last part: no telling, kept together
        });
        match sections.last_mut() {
            Some((_, last_end, names)) if !opens => {
                *last_end = (*last_end).max(stop);
                names.push(name);
            }
            _ => sections.push((part.rva, stop, vec![name])),
        }
    }

    (sections.first().map(|(start, ..)| *start) == Some(first)).then_some(())?;

    let code = code_addresses(restored, model, entry);
    let mut pieces = Vec::new();
    for (index, (start, _, names)) in sections.iter().enumerate() {
        let next = sections.get(index + 1).map_or(end, |(next, ..)| *next);
        let name = SECTION_NAMES
            .iter()
            .find(|wanted| names.iter().any(|name| name.as_slice() == **wanted))
            .map_or_else(
                || names.first().cloned().unwrap_or_default(),
                |name| name.to_vec(),
            );

        let runs = code.iter().any(|rva| (*start..next).contains(rva));
        let kind = match named_kind(names) {
            Some(SectionKind::Code) => SectionKind::Code,
            Some(kind) if !runs => kind,
            _ => SectionKind::WritableCode, // names give no permissions: the superset
        };

        let mut padded = [0u8; 8];
        padded.get_mut(..name.len())?.copy_from_slice(&name);
        pieces.push(PlannedSection {
            name: padded,
            start: *start,
            end: next,
            kind,
        });
    }

    let last = sections.last()?;
    let tail = last.1.checked_next_multiple_of(alignment)?; // linker writes .reloc last, no parts
    if tail < end {
        pieces.last_mut()?.end = tail;
        let (name, kind) = match tail_holds_relocations(restored, model, tail, end) {
            true => (*b".reloc\0\0", SectionKind::Relocations),
            false => ([0; 8], SectionKind::WritableCode), // not from the linker's groups
        };
        pieces.push(PlannedSection {
            name,
            start: tail,
            end,
            kind,
        });
    }

    let runs_code = entry.is_none_or(|entry| {
        pieces.iter().any(|piece| {
            matches!(piece.kind, SectionKind::Code | SectionKind::WritableCode)
                && (piece.start..piece.end).contains(&entry)
        })
    });
    runs_code.then_some(pieces)
}

fn tail_holds_relocations(restored: &[u8], model: &PeModel, tail: usize, end: usize) -> bool {
    let listed = model
        .directory_offset(BASERELOC_DIRECTORY)
        .and_then(|offset| read_u32(restored, offset).ok())
        .map(|rva| rva as usize)
        .filter(|rva| *rva != 0 && *rva < end);

    match listed {
        Some(start) => (tail..end).contains(&start),
        None => {
            let rest = restored.get(tail..end);
            rest.is_some_and(|rest| rest.iter().all(|byte| *byte == 0))
                || relocations_intact(restored, tail, end - tail)
        }
    }
}

pub(crate) fn pogo_tls_directory(parts: &[CoffGroup]) -> Option<usize> {
    unique(
        parts
            .iter()
            .filter(|part| part.name == TLS_PART)
            .map(|part| part.rva),
    )
}

pub(super) fn pogo_data(bytes: &[u8], at: usize, image: &Range<usize>) -> bool {
    let signature = bytes.get(at..at.saturating_add(POGO_RECORDS));
    let first = read_u32(bytes, at.saturating_add(POGO_RECORDS)).map(|rva| rva as usize);

    signature.is_some_and(|signature| POGO_SIGNATURES.contains(&signature))
        && first.is_ok_and(|rva| image.contains(&rva))
        && bytes.get(at.saturating_add(POGO_FIRST_NAME)) == Some(&b'.')
}
