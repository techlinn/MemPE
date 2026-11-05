use super::debug::{DEBUG_ADDRESS_OFFSET, DEBUG_ENTRY_SIZE, DEBUG_SIZE_OFFSET, DEBUG_TYPE_OFFSET};
use super::sections::{
    CODE_SECTION, DATA_SECTION, READ_ONLY_SECTION, RELOCATION_SECTION, RESOURCE_SECTION,
    SectionPiece,
};
use super::{FIRST_SECTION_RVA, SCAN_STEP, unique};
use crate::pe::image::read_u32;
use crate::pe::{DEBUG_DIRECTORY, PeModel};

pub(super) const DEBUG_TYPE_POGO: u32 = 13;
const POGO_SIGNATURES: [&[u8]; 5] = [b"\0\0\0\0", b"\0UGP", b"\0IGP", b"\0OGP", b"GCTL"]; // none, PGU, PGI, PGO and LTCG
const POGO_RECORDS: usize = 4;
const POGO_FIRST_NAME: usize = 12;
const POGO_RECORD_HEADER: usize = 8;
const MAX_POGO_NAME: usize = 64;
const MAX_POGO_PARTS: usize = 4_096;
const MIN_POGO_PARTS: usize = 3;
const TLS_PART: &[u8] = b".rdata$T"; // where msvc places _tls_used, the tls directory
const READ_ONLY_PARTS: [&[u8]; 9] = [
    b".rdata", b".idata", b".CRT", b".00cfg", b".rtc", b".xdata", b".edata", b".didat", b".tls",
];
const WRITABLE_PARTS: [&[u8]; 2] = [b".data", b".bss"];
const SECTION_NAMES: [&[u8]; 3] = [b".text", b".rdata", b".data"]; // a section holding one of these parts takes its name, code first

pub(crate) struct PogoPart {
    pub(crate) rva: usize,
    pub(crate) size: usize,
    pub(crate) name: Vec<u8>,
}

pub(crate) fn pogo_parts(bytes: &[u8], model: &PeModel, end: usize) -> Option<Vec<PogoPart>> {
    let listed = model
        .directory(bytes, DEBUG_DIRECTORY)
        .ok()
        .flatten()
        .and_then(|directory| {
            let start = directory.rva().as_usize();
            (0..directory.size() as usize / DEBUG_ENTRY_SIZE).find_map(|index| {
                let entry = start.checked_add(index.checked_mul(DEBUG_ENTRY_SIZE)?)?;
                (read_u32(bytes, entry.checked_add(DEBUG_TYPE_OFFSET)?).ok()? == DEBUG_TYPE_POGO)
                    .then_some(())?;
                let rva = read_u32(bytes, entry.checked_add(DEBUG_ADDRESS_OFFSET)?).ok()? as usize;
                let size = read_u32(bytes, entry.checked_add(DEBUG_SIZE_OFFSET)?).ok()? as usize;
                Some(rva..rva.checked_add(size)?)
            })
        });

    let found = listed.or_else(|| {
        unique(
            (FIRST_SECTION_RVA..end)
                .step_by(SCAN_STEP)
                .filter(|at| {
                    pogo_data(bytes, *at, end)
                        && read_u32(bytes, at + POGO_RECORDS) == Ok(FIRST_SECTION_RVA as u32)
                })
                .map(|at| at..end),
        )
    })?; // a wiped debug directory leaves the data behind

    let mut parts: Vec<PogoPart> = Vec::new();
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
    previous: Option<&PogoPart>,
) -> Option<(PogoPart, usize)> {
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

    let part = PogoPart {
        rva,
        size,
        name: name.to_vec(),
    };
    Some((part, next))
}

pub(crate) fn pogo_sections(
    parts: &[PogoPart],
    model: &PeModel,
    end: usize,
    entry: Option<usize>,
) -> Option<Vec<SectionPiece>> {
    let alignment = model.section_alignment as usize;
    let first = model.sections().first()?.virtual_address().as_usize();

    let prefix = |name: &[u8]| -> Vec<u8> {
        name.split(|byte| *byte == b'$')
            .next()
            .unwrap_or(name)
            .to_vec()
    };
    let class = |prefix: &[u8]| -> Vec<u8> {
        match prefix {
            read_only if READ_ONLY_PARTS.contains(&read_only) => b".rdata".to_vec(),
            writable if WRITABLE_PARTS.contains(&writable) => b".data".to_vec(),
            other => other.to_vec(),
        }
    }; // a new class on a fresh page opens a section

    let mut sections: Vec<(usize, usize, Vec<Vec<u8>>)> = Vec::new(); // start, end of its parts, part names
    for part in parts.iter().filter(|part| part.rva < end) {
        let stop = part.rva.checked_add(part.size)?.min(end); // past the merged range the packer kept its own sections
        let name = prefix(&part.name);
        let opens = sections.last().is_none_or(|(_, last_end, names)| {
            let previous = names.last().map(|last| class(last));
            part.rva.is_multiple_of(alignment)
                && part.rva >= *last_end
                && (part.rva > *last_end || previous != Some(class(&name)))
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

    let named = sections.iter().map(|(start, stop, names)| {
        let name = SECTION_NAMES
            .iter()
            .find(|wanted| names.iter().any(|name| name.as_slice() == **wanted))
            .map_or_else(
                || names.first().cloned().unwrap_or_default(),
                |name| name.to_vec(),
            );
        (*start, *stop, name)
    });
    let sections = named.collect::<Vec<_>>();

    let mut pieces = Vec::new();
    for (index, (start, _, name)) in sections.iter().enumerate() {
        let next = sections.get(index + 1).map_or(end, |(next, ..)| *next);
        let characteristics = match name.as_slice() {
            b".text" => CODE_SECTION,
            b".rdata" | b".pdata" => READ_ONLY_SECTION,
            b".rsrc" => RESOURCE_SECTION,
            _ => DATA_SECTION,
        };

        let mut padded = [0u8; 8];
        padded.get_mut(..name.len())?.copy_from_slice(name);
        pieces.push(SectionPiece {
            name: padded,
            start: *start,
            end: next,
            characteristics,
        });
    }

    let last = sections.last()?;
    let tail = last.1.checked_next_multiple_of(alignment)?; // the linker writes .reloc last and gives it no parts
    if tail < end {
        pieces.last_mut()?.end = tail;
        pieces.push(SectionPiece {
            name: *b".reloc\0\0",
            start: tail,
            end,
            characteristics: RELOCATION_SECTION,
        });
    }

    let runs_code = entry.is_none_or(|entry| {
        pieces.iter().any(|piece| {
            piece.characteristics == CODE_SECTION && (piece.start..piece.end).contains(&entry)
        })
    });
    runs_code.then_some(pieces)
}

pub(crate) fn pogo_tls_directory(parts: &[PogoPart]) -> Option<usize> {
    unique(
        parts
            .iter()
            .filter(|part| part.name == TLS_PART)
            .map(|part| part.rva),
    )
}

pub(super) fn pogo_data(bytes: &[u8], at: usize, end: usize) -> bool {
    let signature = bytes.get(at..at.saturating_add(POGO_RECORDS));
    let first = read_u32(bytes, at.saturating_add(POGO_RECORDS)).map(|rva| rva as usize);

    signature.is_some_and(|signature| POGO_SIGNATURES.contains(&signature))
        && first.is_ok_and(|rva| (FIRST_SECTION_RVA..end).contains(&rva))
        && bytes.get(at.saturating_add(POGO_FIRST_NAME)) == Some(&b'.')
}
