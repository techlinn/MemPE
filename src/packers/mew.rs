use std::collections::HashSet;
use std::ops::Range;

use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind};

use super::Packer;
use super::merged_sections::{
    ESI, ListedImports, Load, MAX_CANDIDATES, MAX_STREAMS, MODIFIED_STUB, MergedImage, TOO_MANY,
    Undecided, address, blank_program, consensus, consensus_decoding, mapped_file, outside,
    place_stream, refused, register_load, restore, write_entry,
};
use crate::pe::bytes::{read_u32, write_u32};
use crate::pe::{
    IMAGE_SCN_MEM_WRITE, IMPORT_DIRECTORY, IMPORT_IAT_OFFSET, MAX_IMPORT_DESCRIPTORS, MAX_IMPORTS,
    PeImage, PeKind, PeModel, Rva, SECTION_CHARACTERISTICS_OFFSET, SectionModel,
};
use crate::unpack::codecs::call_filter::{self, CallFilter, Stored};
use crate::unpack::codecs::{DecodeError, lzma};
use crate::unpack::tables::{
    THUNK_SIZE, clear_header_slack, first_section_range, imports_from_original, is_module_name,
    lowest_leaf_below, read_c_string,
};
use crate::unpack::x86::opcodes::MOV_REG_IMM32;
use crate::unpack::{
    ImportedFunction, InitialData, ModuleImports, Origin, PACKER_HEADER_BYTES, PackerId,
    PackerImports, PackerReport, Part, Step, Unpacked, find_pattern, hex, need, pattern_at,
    with_initial_data,
};

const NAME: PackerId = PackerId::Mew;
const STUB_11: &str = hex("BE ?? ?? ?? ?? 8B DE AD AD 50 AD 97 B2 80");
const STUB_10: &str = hex("BE ?? ?? ?? ?? AC 91 AD 95 AD 92 AD 51 56 87 F2 97 FC B2 80 33 DB");
const STUB_5: &str = hex("BE ?? ?? ?? ?? AD 91 AD 93 53 AD 96 56 5F AC C0 C0 ?? 04 ?? C0 C8 ?? AA");
const MAX_STUB_STEPS: usize = 64; // stock loop is the fifth instruction after the load
const DECRYPT_5: &str = hex("AC C0 C0 ?? 04 ?? C0 C8 ?? AA"); // lodsb, rol, add, ror, stosb
const MODIFIED_11: &str = "11 SE (modified stub)";
const MODIFIED_10: &str = "10 (modified stub)";
const MODIFIED_5: &str = "5 (modified stub)";
const STOCK_5: &str = "5";
const MOV_ESI: u8 = MOV_REG_IMM32 + ESI;
const ASSUMED_LZMA: &str = "decoded with LZMA properties not checked against the stub";
const NAMES_BY_EXTENSION: &str = "module names told from function names by their extension";
const SEVERAL_TABLES: &str = "several tables fit the decrypt stub";
const NO_DECRYPT_LOOP: &str = "no decrypt loop follows the table load";
const MAX_LZMA_BLOCKS: usize = 256;
const ENTRY_11: usize = 4;
const STREAMS_11: usize = 8;
const SOURCE_10: usize = 5;
const STREAMS_10: usize = 9;
const ENTRY_10: usize = 8;
const LZMA_BLOCK_HEADER: usize = 13; // size, destination, packed size, skipped byte
const LZMA_PROPERTIES: lzma::Properties = lzma::Properties {
    literal_context: 4,
    literal_position: 0,
    position: 2,
};
const NAME_ENTRY: u8 = 0x80; // high bit: name
const NEXT_MODULE: u32 = u32::MAX;
const BACKWARD_ORDINAL: u8 = 1;
const BACKWARD_END: u8 = 2;
const BACKWARD_REWIND: usize = 4;
const BACKWARD_STEP: usize = 2;
const MAX_BACKWARD_BYTES: usize = 0x10_0000;
const KEY_OFFSETS: [usize; 3] = [3, 5, 8]; // rol, add, ror operands
const TABLE_ENTRY_5: usize = 4;
const TABLE_START_5: usize = 8;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Eleven,
    Ten,
}

struct Packed<'a> {
    bytes: &'a [u8],
    base: usize,
    image: Range<usize>,
}

impl Packed<'_> {
    fn address(&self, at: usize) -> Option<usize> {
        address(self.bytes, at, self.base)
    }

    fn holds(&self, rva: usize) -> bool {
        rva < self.bytes.len()
    }
}

struct Candidate {
    table: usize,
    stock: Option<Kind>,
}

struct Encrypted<'a> {
    range: Range<usize>,
    entry: usize,
    section: &'a SectionModel,
    stock: bool,
    keys: Option<[u8; 3]>,
}

#[derive(PartialEq)]
struct Decoded {
    kind: Kind,
    image: Vec<u8>,
    entry: usize,
    written: Vec<Range<usize>>,
    imports: usize,
    beneath_imports: Option<(usize, Vec<u8>)>,
    lzma: bool,
}

fn unpack(image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
    let model = image.model();
    (model.kind == PeKind::Pe32).then_some(())?;
    if model.sections.first()?.raw_size != 0 {
        return unpack_encrypted(image, origin);
    }

    let image_range = first_section_range(model)?;
    let packed = Packed {
        bytes: image.bytes(),
        base: origin.base,
        image: image_range.clone(),
    };
    let candidates = find_candidates(&packed);
    candidates.first()?;
    let stock = candidates.iter().find_map(|candidate| candidate.stock);
    let label = stock.map_or(MODIFIED_STUB, |kind| version(kind, true));
    if candidates.len() > MAX_CANDIDATES {
        return stock.and_then(|_| refused(NAME, label, TOO_MANY));
    }

    let decode_all = |bytes: &[u8]| {
        let packed = &Packed {
            bytes,
            base: origin.base,
            image: image_range.clone(),
        };
        consensus(candidates.iter().flat_map(|candidate| {
            kinds(candidate.stock).map(move |kind| decode_as(packed, candidate, kind))
        }))
    };
    let (version, decoded) = match consensus_decoding(image, origin, decode_all) {
        Ok(found) => found,
        Err(Undecided::Failed(why)) => {
            return stock.and_then(|_| refused(NAME, label, why.describe())); // no stock stub: may be chance
        }
        Err(why) => return refused(NAME, label, why.describe()),
    };

    let imports = match decoded.kind {
        Kind::Eleven => forward_imports(&decoded.image, decoded.imports, origin.base),
        Kind::Ten => backward_imports(&decoded.image, decoded.imports, origin.base),
    };
    let page = model.section_alignment as usize;
    let iat_page = imports
        .as_ref()
        .and_then(|imports| {
            imports
                .modules
                .iter()
                .map(|module| module.first_thunk)
                .min()
        })
        .map(|iat| iat as usize / page * page);
    let sections_data: Vec<&Range<usize>> = decoded
        .written
        .iter()
        .filter(|written| image_range.contains(&written.start) && written.start != decoded.imports)
        .collect();
    let resource_start =
        lowest_leaf_below(&decoded.image, model, image_range.end).map(|leaf| leaf / page * page);
    let section_starts = sections_data
        .iter()
        .filter(|written| resource_start.is_none_or(|resources| written.start < resources))
        .map(|written| written.start)
        .chain(iat_page) // lzma: whole image in one block
        .chain(resource_start)
        .collect();

    restore(
        image,
        origin,
        MergedImage {
            name: NAME,
            version,
            entry: decoded.entry,
            entry_inferred: None,
            program_inferred: decoded.lzma.then_some(ASSUMED_LZMA),
            program: image_range.clone(),
            image_end: image_range.end,
            original: decoded.image,
            beneath_imports: decoded.beneath_imports,
            imports,
            section_starts: Some(section_starts),
            keeps_code_fields: false,
        },
    )
}

fn version(kind: Kind, stock: bool) -> &'static str {
    match (kind, stock) {
        (Kind::Eleven, true) => "11 SE",
        (Kind::Eleven, false) => MODIFIED_11,
        (Kind::Ten, true) => "10",
        (Kind::Ten, false) => MODIFIED_10,
    }
}

fn kinds(stock: Option<Kind>) -> impl Iterator<Item = Kind> {
    [Kind::Eleven, Kind::Ten]
        .into_iter()
        .filter(move |kind| stock.is_none_or(|stock| stock == *kind))
}

fn decode_as(
    packed: &Packed<'_>,
    candidate: &Candidate,
    kind: Kind,
) -> Result<(&'static str, Decoded), DecodeError> {
    let decoded = match kind {
        Kind::Eleven => decode_11(packed, candidate.table),
        Kind::Ten => decode_10(packed, candidate.table),
    }?;

    Ok((version(kind, candidate.stock.is_some()), decoded))
}

fn find_candidates(packed: &Packed<'_>) -> Vec<Candidate> {
    let outside = outside(&packed.image, packed.bytes.len());
    let mut tables = HashSet::new();
    let found = outside
        .into_iter()
        .flatten()
        .filter_map(|at| register_load(packed.bytes, at))
        .filter(|load| load.register == ESI)
        .filter_map(|load| candidate(packed, &load))
        .filter(|candidate| tables.insert(candidate.table));

    let mut stock = Vec::new();
    let mut modified = Vec::new();
    for candidate in found {
        let list = match candidate.stock {
            Some(_) => &mut stock,
            None => &mut modified,
        };
        if list.len() <= MAX_CANDIDATES {
            list.push(candidate);
        }
    }

    stock.extend(modified);
    stock.truncate(MAX_CANDIDATES + 1); // one over: the caller refuses
    stock
}

fn candidate(packed: &Packed<'_>, load: &Load) -> Option<Candidate> {
    let table = load.value.checked_sub(packed.base)?;
    (!packed.image.contains(&table) && packed.holds(table)).then_some(())?;

    let stock = match (
        pattern_at(packed.bytes, load.at, STUB_11),
        pattern_at(packed.bytes, load.at, STUB_10),
    ) {
        (true, _) => Some(Kind::Eleven),
        (_, true) => Some(Kind::Ten),
        _ => None,
    };
    (stock.is_some() || plausible(packed, table)).then_some(Candidate { table, stock })
}

fn plausible(packed: &Packed<'_>, table: usize) -> bool {
    let entry = packed.address(table.saturating_add(ENTRY_11));
    let first = packed.address(table.saturating_add(STREAMS_11));
    let eleven = entry.is_some_and(|entry| packed.image.contains(&entry))
        && first.is_some_and(|first| packed.holds(first));

    let count = packed.bytes.get(table).copied().map(usize::from);
    let source = packed.address(table.saturating_add(SOURCE_10));
    let ten = count.is_some_and(|count| (1..=MAX_STREAMS).contains(&count))
        && source.is_some_and(|source| !packed.image.contains(&source) && packed.holds(source));

    eleven || ten
}

fn decode_11(packed: &Packed<'_>, table: usize) -> Result<Decoded, DecodeError> {
    let entry = packed
        .address(table.checked_add(ENTRY_11).ok_or(DecodeError::Corrupt)?)
        .ok_or(DecodeError::Corrupt)?;
    if !packed.image.contains(&entry) {
        return Err(DecodeError::Corrupt);
    }

    let mut image = blank_program(packed.bytes, &packed.image)?;
    let mut written = Vec::new();
    let mut beneath = Vec::new();
    let mut saved_bytes = 0usize;
    let mut at = table.checked_add(STREAMS_11).ok_or(DecodeError::Corrupt)?;

    loop {
        let destination = read_u32(packed.bytes, at).map_err(|_| DecodeError::Truncated)? as usize;
        at = at.checked_add(4).ok_or(DecodeError::Corrupt)?;
        if destination == 0 {
            break;
        }
        if written.len() >= MAX_STREAMS {
            return Err(DecodeError::Corrupt);
        }

        let destination = destination
            .checked_sub(packed.base)
            .ok_or(DecodeError::Corrupt)?;
        let end = image.len();
        let placed = place_stream(packed.bytes, at, &mut image, destination, end)?;
        at = at
            .checked_add(placed.consumed)
            .ok_or(DecodeError::Corrupt)?;

        saved_bytes = saved_bytes.saturating_add(placed.beneath.len());
        if saved_bytes > packed.bytes.len() {
            return Err(DecodeError::Corrupt);
        }
        beneath.push((destination, placed.beneath));
        written.push(placed.range);
    }

    let lzma = written
        .iter()
        .any(|range| !packed.image.contains(&range.start)); // lzma mode unpacks its decoder past the image
    if lzma {
        at = decode_lzma_blocks(packed, &mut image, at, &mut written)?;
    }

    let imports = packed.address(at).ok_or(DecodeError::Corrupt)?;
    if !packed.image.contains(&imports) {
        return Err(DecodeError::Corrupt);
    }
    Ok(Decoded {
        kind: Kind::Eleven,
        image,
        entry,
        written,
        imports,
        beneath_imports: beneath.into_iter().find(|(at, _)| *at == imports),
        lzma,
    })
}

fn decode_lzma_blocks(
    packed: &Packed<'_>,
    image: &mut [u8],
    mut at: usize,
    written: &mut Vec<Range<usize>>,
) -> Result<usize, DecodeError> {
    let first = read_u32(packed.bytes, at).map_err(|_| DecodeError::Truncated)? as usize;
    let filter_span = (first < packed.base).then_some(first); // filtered layout opens with a length
    if filter_span.is_some() {
        at = at.checked_add(4).ok_or(DecodeError::Corrupt)?;
    }
    at = at.checked_add(4).ok_or(DecodeError::Corrupt)?;

    for _ in 0..MAX_LZMA_BLOCKS {
        let size = read_u32(packed.bytes, at).map_err(|_| DecodeError::Truncated)? as usize;
        if size == 0 {
            return at.checked_add(4).ok_or(DecodeError::Corrupt);
        }

        let destination = packed
            .address(at.checked_add(4).ok_or(DecodeError::Corrupt)?)
            .ok_or(DecodeError::Corrupt)?;
        let range = destination..destination.checked_add(size).ok_or(DecodeError::Corrupt)?;
        image.get(range.clone()).ok_or(DecodeError::Truncated)?;

        let packed_size = read_u32(
            packed.bytes,
            at.checked_add(8).ok_or(DecodeError::Truncated)?,
        )
        .map_err(|_| DecodeError::Truncated)? as usize;
        let start = at
            .checked_add(LZMA_BLOCK_HEADER)
            .ok_or(DecodeError::Corrupt)?;
        let source = packed
            .bytes
            .get(
                start
                    ..start
                        .checked_add(packed_size)
                        .ok_or(DecodeError::Truncated)?,
            )
            .ok_or(DecodeError::Truncated)?;
        let mut data = lzma::decompress(source, &LZMA_PROPERTIES, size)?;
        if let Some(span) = filter_span {
            call_filter::undo(
                &mut data,
                span,
                CallFilter {
                    marks: None,
                    stored: Stored::Be32,
                    counted_from: 1,
                },
            );
        }

        image
            .get_mut(range.clone())
            .ok_or(DecodeError::Truncated)?
            .copy_from_slice(&data);
        written.push(range);
        at = start.checked_add(packed_size).ok_or(DecodeError::Corrupt)?;
        if filter_span.is_some() {
            return Ok(at);
        }
    }

    Err(DecodeError::Corrupt)
}

fn decode_10(packed: &Packed<'_>, table: usize) -> Result<Decoded, DecodeError> {
    let count = usize::from(*packed.bytes.get(table).ok_or(DecodeError::Truncated)?);
    if !(1..=MAX_STREAMS).contains(&count) {
        return Err(DecodeError::Corrupt);
    }

    let mut source = packed
        .address(table.checked_add(SOURCE_10).ok_or(DecodeError::Corrupt)?)
        .ok_or(DecodeError::Corrupt)?;
    let mut image = blank_program(packed.bytes, &packed.image)?;
    let mut written = Vec::with_capacity(count);
    let slot = |index: usize| {
        let at = index.checked_mul(4)?.checked_add(STREAMS_10)?;
        packed.address(table.checked_add(at)?)
    };

    for index in 0..count {
        let destination = slot(index).ok_or(DecodeError::Corrupt)?;
        let end = image.len();
        let placed = place_stream(packed.bytes, source, &mut image, destination, end)?;
        source = source
            .checked_add(placed.consumed)
            .ok_or(DecodeError::Corrupt)?;
        written.push(placed.range);
    }

    let stage = slot(count).ok_or(DecodeError::Corrupt)?;
    if *image.get(stage).ok_or(DecodeError::Truncated)? != MOV_ESI {
        return Err(DecodeError::Corrupt);
    }
    let pointer = |at: Option<usize>| {
        at.and_then(|at| address(&image, at, packed.base))
            .ok_or(DecodeError::Corrupt)
    };
    let imports = pointer(stage.checked_add(1))?;
    let entry = pointer(imports.checked_add(ENTRY_10))?;
    if !packed.image.contains(&entry) {
        return Err(DecodeError::Corrupt);
    }

    Ok(Decoded {
        kind: Kind::Ten,
        image,
        entry,
        written,
        imports,
        beneath_imports: None,
        lzma: false,
    })
}

fn forward_imports(image: &[u8], mut at: usize, base: usize) -> Option<ListedImports> {
    let start = at;
    let mut modules = Vec::new();
    let mut budget = MAX_IMPORTS;

    for _ in 0..MAX_IMPORT_DESCRIPTORS {
        let iat = address(image, at, base)?;
        let (module, next) = read_c_string(image, at.checked_add(4)?)?;
        at = next;

        let mut functions = Vec::new();
        let end = loop {
            budget = budget.checked_sub(1)?;
            let value = u32::from_be_bytes(image.get(at..at.checked_add(4)?)?.try_into().ok()?);
            if value == NEXT_MODULE {
                at = at.checked_add(4)?;
                break None;
            }

            if *image.get(at)? >= NAME_ENTRY {
                let name_start = at.checked_add(1)?;
                if *image.get(name_start)? == 0 {
                    break Some(name_start.checked_add(1)?);
                }

                let (name, next) = read_c_string(image, name_start)?;
                functions.push(ImportedFunction::Name(name));
                at = next;
                continue;
            }

            at = at.checked_add(4)?;
            let ordinal = u16::try_from(value.checked_add(1)?).ok()?; // stored minus one
            functions.push(ImportedFunction::Ordinal(ordinal));
        };

        modules.push(ModuleImports {
            module: Some(module),
            first_thunk: u32::try_from(iat).ok()?,
            functions,
        });

        if let Some(end) = end {
            return Some(ListedImports {
                modules,
                end_markers: Vec::new(),
                written: start..end,
                names_end: 0,
                inferred: None,
            });
        }
    }

    None
}

fn backward_imports(image: &[u8], table: usize, base: usize) -> Option<ListedImports> {
    let mut slot = address(image, table, base)?; // one slot before the first iat
    let mut modules: Vec<ModuleImports> = Vec::new();
    let mut cursor = table.checked_sub(BACKWARD_REWIND)?;

    for _ in 0..MAX_BACKWARD_BYTES {
        cursor = cursor.checked_sub(BACKWARD_STEP)?;
        let marker = *image.get(cursor)?;
        cursor = cursor.checked_add(1)?; // stub walks back two, reads one forward

        let function = match marker {
            BACKWARD_END => {
                return (!modules.is_empty()).then_some(ListedImports {
                    modules,
                    end_markers: Vec::new(),
                    written: 0..0,
                    names_end: 0,
                    inferred: Some(NAMES_BY_EXTENSION),
                });
            }
            BACKWARD_ORDINAL => {
                let ordinal = read_u32(image, cursor).ok()?;
                ImportedFunction::Ordinal(u16::try_from(ordinal).ok()?)
            }
            0 if is_module_name(image, cursor) => {
                slot = slot.checked_add(THUNK_SIZE)?;
                modules.push(ModuleImports {
                    module: Some(read_c_string(image, cursor)?.0),
                    first_thunk: u32::try_from(slot).ok()?,
                    functions: Vec::new(),
                });
                cursor = cursor.checked_sub(BACKWARD_REWIND)?;
                continue;
            }
            0 => ImportedFunction::Name(read_c_string(image, cursor)?.0),
            _ => continue,
        };

        modules.last_mut()?.functions.push(function);
        slot = slot.checked_add(THUNK_SIZE)?;
        cursor = cursor.checked_sub(BACKWARD_REWIND)?;
    }

    None
}

// the loop the stub runs next, its jumps followed: modified stubs move it into a cave
fn stub_keys(bytes: &[u8], load_at: usize) -> Option<[u8; 3]> {
    let decryptor = next_decrypt_loop(bytes, load_at)?;

    let keys = KEY_OFFSETS.map(|offset| bytes.get(decryptor.checked_add(offset)?).copied());
    let [Some(left), Some(add), Some(right)] = keys else {
        return None;
    };
    Some([left, add, right])
}

fn next_decrypt_loop(bytes: &[u8], load_at: usize) -> Option<usize> {
    let mut at = load_at;

    for _ in 0..MAX_STUB_STEPS {
        if pattern_at(bytes, at, DECRYPT_5) {
            return Some(at);
        }

        let code = bytes.get(at..)?;
        let instruction = Decoder::with_ip(32, code, at as u64, DecoderOptions::NONE).decode();
        at = match instruction.flow_control() {
            FlowControl::Next => usize::try_from(instruction.next_ip()).ok()?,
            FlowControl::UnconditionalBranch if instruction.op0_kind() != OpKind::FarBranch32 => {
                usize::try_from(instruction.near_branch_target()).ok()?
            }
            _ => return None, // anything else leaves the straight path the stub takes
        };
    }

    None
}

fn kept_imports(restored: &mut [u8], memory: &[u8], model: &PeModel) -> Option<PackerImports> {
    let directory = model.directory(restored, IMPORT_DIRECTORY)?;
    imports_from_original(
        restored,
        model,
        directory.rva().as_usize(),
        &mut &memory[..],
    )
}

fn unpack_encrypted(image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
    let model = image.model();
    find_pattern(image.bytes(), DECRYPT_5)?;

    let refuse =
        |version: &str, refusal| Unpacked::refused(NAME, Some(version.to_owned()), refusal);
    let encrypted = match find_encrypted(image.bytes(), origin.base, model)? {
        Ok(encrypted) => encrypted,
        Err(refusal) => return Some(refuse(STOCK_5, refusal)),
    };
    let version = match encrypted.stock {
        true => STOCK_5,
        false => MODIFIED_5,
    };

    let restored = restore_encrypted(image, origin, encrypted, version);
    Some(restored.unwrap_or_else(|refusal| refuse(version, refusal)))
}

fn restore_encrypted(
    image: &PeImage<'_>,
    origin: &Origin<'_>,
    encrypted: Encrypted<'_>,
    version: &'static str,
) -> Step<Unpacked> {
    let model = image.model();
    let Encrypted {
        range,
        entry,
        section,
        keys,
        ..
    } = encrypted;
    let [left, add, right] = need(keys, NO_DECRYPT_LOOP)?;
    let decrypt = |byte: u8| {
        byte.rotate_left(u32::from(left) % 8)
            .wrapping_add(add)
            .rotate_right(u32::from(right) % 8)
    };

    let linked_base = origin.linked_base();
    let file = origin.read_file().and_then(|file| mapped_file(file, image));
    let pristine = file.and_then(|mut file| {
        file.get_mut(range.clone())?
            .iter_mut()
            .for_each(|byte| *byte = decrypt(*byte));
        Some(file)
    });
    let in_memory = need(
        image.bytes().get(range.clone()),
        "the encrypted section is not in the image",
    )?;
    let decrypted_in_memory = stub_decrypted(in_memory, decrypt);
    let finished = match &pristine {
        Some(pristine) => Some(in_memory) == pristine.get(range.clone()),
        None => decrypted_in_memory.unwrap_or_else(|| loader_ran(image.bytes(), model)),
    };

    let mut restored = image.bytes().to_vec();
    let mut report = PackerReport::new(NAME, Some(version.to_owned()));
    if pristine.is_none() && decrypted_in_memory.is_none() {
        report.failed_with(
            Part::Code,
            "could not tell whether the stub had decrypted it",
        );
    }

    if !finished {
        let from_file = pristine
            .as_deref()
            .and_then(|pristine| pristine.get(range.clone()));
        let code: Vec<u8> = match from_file {
            Some(code) => code.to_vec(),
            None => in_memory.iter().map(|byte| decrypt(*byte)).collect(),
        };
        restored[range.clone()].copy_from_slice(&code); // a copy of the bytes in_memory came from

        match from_file {
            Some(_) => report.restored_with(Part::Code, "from the packed file"),
            None => report.inferred(Part::Code, "decrypted in memory, its state was estimated"),
        }
    }

    write_entry(&mut restored, model, entry)?;
    report.restored(Part::EntryPoint);

    let imports = kept_imports(&mut restored, image.bytes(), model);
    match imports {
        Some(_) => report.restored(Part::Imports),
        None => report.failed(Part::Imports),
    }

    let flags_at = section
        .header_offset
        .saturating_add(SECTION_CHARACTERISTICS_OFFSET);
    let cleared = read_u32(&restored, flags_at)
        .ok()
        .and_then(|flags| write_u32(&mut restored, flags_at, flags & !IMAGE_SCN_MEM_WRITE).ok());
    need(
        cleared,
        "the encrypted section's header is not in the image",
    )?;
    report.inferred(
        Part::SectionFlags,
        "write access taken as added by the packer",
    );

    if clear_header_slack(&mut restored) {
        report.notes.push(PACKER_HEADER_BYTES.to_string());
    }

    let fresh = pristine.filter(|_| finished).and_then(|pristine| {
        with_initial_data(
            image.bytes(),
            &restored,
            InitialData {
                bytes: &pristine,
                base: linked_base?,
            },
            origin.base,
            image.bytes().len(),
            &[],
        )
    });

    Unpacked::restored(restored, report, imports, fresh)
}

// unencrypted code and data are mostly zero bytes
fn stub_decrypted(section: &[u8], decrypt: impl Fn(u8) -> u8) -> Option<bool> {
    let mut counts = [0usize; 256];
    for byte in section {
        counts[usize::from(*byte)] += 1;
    }

    let commonest = (0..=u8::MAX).max_by_key(|byte| counts[usize::from(*byte)])?;
    match (commonest, decrypt(commonest)) {
        (0, 0) => None,
        (0, _) => Some(true),
        (_, 0) => Some(false),
        _ => None,
    }
}

fn loader_ran(memory: &[u8], model: &PeModel) -> bool {
    model
        .directory(memory, IMPORT_DIRECTORY)
        .and_then(|directory| {
            let descriptor = directory.rva().as_usize();
            read_u32(memory, descriptor.checked_add(IMPORT_IAT_OFFSET)?).ok()
        })
        .and_then(|iat| read_u32(memory, iat as usize).ok())
        .is_none_or(|slot| slot >= model.image_size) // loader-bound lookup entries
}

fn find_encrypted<'a>(
    bytes: &[u8],
    base: usize,
    model: &'a PeModel,
) -> Option<Step<Encrypted<'a>>> {
    let mut tables = (0..bytes.len())
        .filter_map(|at| register_load(bytes, at))
        .filter(|load| load.register == ESI)
        .filter_map(|load| encrypted_by(bytes, base, model, &load));

    let first = tables.next()?;
    let agree = tables.all(|other| {
        other.range == first.range && other.entry == first.entry && other.keys == first.keys
    });
    Some(need(agree.then_some(first), SEVERAL_TABLES))
}

fn encrypted_by<'a>(
    bytes: &[u8],
    base: usize,
    model: &'a PeModel,
    load: &Load,
) -> Option<Encrypted<'a>> {
    let table = load.value.checked_sub(base)?;
    let count = read_u32(bytes, table).ok()? as usize;
    let entry = address(bytes, table.checked_add(TABLE_ENTRY_5)?, base)?;
    let start = address(bytes, table.checked_add(TABLE_START_5)?, base)?;
    let last = start.checked_add(count.checked_sub(1)?)?;

    let mapped = |rva: usize, section: &SectionModel| {
        u32::try_from(rva).is_ok_and(|rva| section.contains_rva(Rva(rva)))
    };
    let encrypted = model
        .sections
        .iter()
        .find(|section| section.virtual_address().as_usize() == start)?;
    let entry_mapped = model.sections.iter().any(|section| mapped(entry, section));
    (mapped(last, encrypted) && entry_mapped).then_some(())?;

    Some(Encrypted {
        range: start..last.checked_add(1)?,
        entry,
        section: encrypted,
        stock: pattern_at(bytes, load.at, STUB_5),
        keys: stub_keys(bytes, load.at),
    })
}

pub(super) struct Mew;

impl Packer for Mew {
    fn unpack(&self, image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
        unpack(image, origin)
    }
}
