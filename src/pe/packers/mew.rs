use std::collections::HashSet;
use std::ops::Range;

use super::codecs::bitstream::ByteTags;
use super::codecs::{aplib, lzma};
use super::streamed::{
    ESI, ListedImports, Load, StreamedImage, mapped_file, register_load, restore,
};
use super::tables::{
    IMPORT_IAT_OFFSET, MAX_IMPORT_DESCRIPTORS, MAX_THUNKS, SECTION_CHARACTERISTICS_OFFSET,
    THUNK_SIZE, first_section_range, fresh_image, imports_from_original, is_module_name,
    lowest_moved_leaf, read_c_string,
};
use super::{
    ImportedFunction, ModuleImports, Origin, PackerFindings, PackerImports, PackerReport, Unpacked,
    find_pattern, pattern_at,
};
use crate::pe::image::{read_u32, write_u32};
use crate::pe::parse::parse_memory_image;
use crate::pe::{IMPORT_DIRECTORY, PeImage, PeKind, PeModel, Rva, SectionModel};

const NAME: &str = "MEW";
const STUB_11: &str = "BE ?? ?? ?? ?? 8B DE AD AD 50 AD 97 B2 80";
const STUB_10: &str = "BE ?? ?? ?? ?? AC 91 AD 95 AD 92 AD 51 56 87 F2 97 FC B2 80 33 DB";
const STUB_5: &str = "BE ?? ?? ?? ?? AD 91 AD 93 53 AD 96 56 5F AC C0 C0 ?? 04 ?? C0 C8 ?? AA";
const DECRYPT_5: &str = "AC C0 C0 ?? 04 ?? C0 C8 ?? AA"; // lodsb, rol, add, ror, stosb
const MODIFIED_11: &str = "11 SE (modified stub)";
const MODIFIED_10: &str = "10 (modified stub)";
const MODIFIED_5: &str = "5 (modified stub)";
const MAX_CANDIDATES: usize = 32;
const MAX_STREAMS: usize = 256;
const MAX_LZMA_BLOCKS: usize = 256;
const ENTRY_11: usize = 4;
const STREAMS_11: usize = 8;
const SOURCE_10: usize = 5;
const STREAMS_10: usize = 9;
const ENTRY_10: usize = 8;
const LZMA_BLOCK_HEADER: usize = 13; // size, destination, packed size and a byte the stub skips
const LZMA_PROPERTIES: lzma::Properties = lzma::Properties {
    literal_context: 4,
    literal_position: 0,
    position: 2,
};
const CALL_FILTER_SPAN: usize = 5;
const CALL: u8 = 0xE8;
const JUMP: u8 = 0xE9;
const NAME_ENTRY: u8 = 0x80; // a byte with the high bit set opens a name, a big endian ordinal never does
const NEXT_MODULE: u32 = u32::MAX;
const BACKWARD_ORDINAL: u8 = 1;
const BACKWARD_END: u8 = 2;
const BACKWARD_REWIND: usize = 4;
const BACKWARD_STEP: usize = 2;
const MAX_BACKWARD_BYTES: usize = 0x10_0000;
const KEY_OFFSETS: [usize; 3] = [3, 5, 8]; // rol, add and ror operands in the decrypt loop
const TABLE_ENTRY_5: usize = 4;
const TABLE_START_5: usize = 8;
const WRITABLE: u32 = 0x8000_0000;

#[derive(Clone, Copy)]
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
        (read_u32(self.bytes, at).ok()? as usize).checked_sub(self.base)
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
}

struct Decoded {
    kind: Kind,
    image: Vec<u8>,
    entry: usize,
    written: Vec<Range<usize>>,
    imports: usize,
    beneath_imports: Option<(usize, Vec<u8>)>,
}

pub(super) fn unpack(image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
    let model = image.model();
    (model.kind() == PeKind::Pe32).then_some(())?;
    if model.sections().first()?.raw_size != 0 {
        return unpack_encrypted(image, origin);
    }

    let image_range = first_section_range(model)?;
    let packed = Packed {
        bytes: image.bytes(),
        base: origin.base,
        image: image_range.clone(),
    };
    let candidates = find_candidates(&packed);
    let first_version = match candidates.first()?.stock {
        Some(kind) => version(kind, true),
        None => MODIFIED_11,
    };

    let decode = |bytes: &[u8]| {
        let packed = Packed {
            bytes,
            base: origin.base,
            image: image_range.clone(),
        };
        candidates.iter().find_map(|candidate| {
            let decoded = match candidate.stock {
                Some(Kind::Ten) => decode_10(&packed, candidate.table),
                Some(Kind::Eleven) => decode_11(&packed, candidate.table),
                None => decode_11(&packed, candidate.table)
                    .or_else(|| decode_10(&packed, candidate.table)),
            }?;
            Some((version(decoded.kind, candidate.stock.is_some()), decoded))
        })
    };
    let decoded = decode(image.bytes()).or_else(|| {
        let file = origin.read_file()?;
        decode(&mapped_file(&file, image)?)
    }); // mew never overwrites its packed data
    let Some((version, decoded)) = decoded else {
        return Some(Unpacked::detected_only(
            NAME,
            Some(first_version.to_owned()),
            "image (its packed data could not be decoded)",
        ));
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
        lowest_moved_leaf(&decoded.image, model, image_range.end).map(|leaf| leaf / page * page); // the leaves mew keeps stay where they were, past any data
    let section_starts = sections_data
        .iter()
        .filter(|written| resource_start.is_none_or(|resources| written.start < resources)) // later ones are leaves
        .map(|written| written.start / page * page) // streams skip an iat the section opens with
        .chain(iat_page) // lzma keeps the whole image in one block
        .chain(resource_start)
        .collect();

    restore(
        image,
        origin,
        StreamedImage {
            name: NAME,
            version,
            entry: decoded.entry,
            image: image_range.clone(),
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

fn find_candidates(packed: &Packed<'_>) -> Vec<Candidate> {
    let outside = [0..packed.image.start, packed.image.end..packed.bytes.len()];
    let mut tables = HashSet::new();
    let mut candidates: Vec<Candidate> = outside
        .into_iter()
        .flatten()
        .filter_map(|at| register_load(packed.bytes, at))
        .filter(|load| load.register == ESI)
        .filter_map(|load| candidate(packed, &load))
        .filter(|candidate| tables.insert(candidate.table)) // a decoy load repeated many times is still one table
        .take(MAX_CANDIDATES)
        .collect();

    candidates.sort_by_key(|candidate| candidate.stock.is_none());
    candidates
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

fn decode_11(packed: &Packed<'_>, table: usize) -> Option<Decoded> {
    let entry = packed.address(table.checked_add(ENTRY_11)?)?;
    packed.image.contains(&entry).then_some(())?;

    let mut image = packed.bytes.to_vec();
    image.get_mut(packed.image.clone())?.fill(0); // streams only cover initialized data
    let mut written = Vec::new();
    let mut beneath = Vec::new();
    let mut at = table.checked_add(STREAMS_11)?;

    loop {
        let destination = read_u32(packed.bytes, at).ok()? as usize;
        at = at.checked_add(4)?;
        if destination == 0 {
            break;
        }
        (written.len() < MAX_STREAMS).then_some(())?;

        let destination = destination.checked_sub(packed.base)?;
        let mut tags = ByteTags::new(packed.bytes.get(at..)?);
        let limit = image.len().checked_sub(destination)?;
        let decoded = aplib::decompress(&mut tags, limit, aplib::Variant::Classic)?;
        at = at.checked_add(tags.position())?;

        let range = destination..destination.checked_add(decoded.len())?;
        let target = image.get_mut(range.clone())?;
        beneath.push((destination, target.to_vec()));
        target.copy_from_slice(&decoded);
        written.push(range);
    }

    let lzma = written
        .iter()
        .any(|range| !packed.image.contains(&range.start)); // lzma mode unpacks its own decoder past the image
    if lzma {
        at = decode_lzma_blocks(packed, &mut image, at, &mut written)?;
    }

    let imports = packed.address(at)?;
    packed.image.contains(&imports).then_some(())?;
    Some(Decoded {
        kind: Kind::Eleven,
        image,
        entry,
        written,
        imports,
        beneath_imports: beneath.into_iter().find(|(at, _)| *at == imports),
    })
}

fn decode_lzma_blocks(
    packed: &Packed<'_>,
    image: &mut [u8],
    mut at: usize,
    written: &mut Vec<Range<usize>>,
) -> Option<usize> {
    let first = read_u32(packed.bytes, at).ok()? as usize;
    let filter_span = (first < packed.base).then_some(first); // the filtered layout opens with a length, the plain one with an address
    if filter_span.is_some() {
        at = at.checked_add(4)?;
    }
    at = at.checked_add(4)?; // where the stub keeps its probabilities

    for _ in 0..MAX_LZMA_BLOCKS {
        let size = read_u32(packed.bytes, at).ok()? as usize;
        if size == 0 {
            return at.checked_add(4);
        }

        let destination = packed.address(at.checked_add(4)?)?;
        let range = destination..destination.checked_add(size)?;
        image.get(range.clone())?;

        let packed_size = read_u32(packed.bytes, at.checked_add(8)?).ok()? as usize;
        let start = at.checked_add(LZMA_BLOCK_HEADER)?;
        let source = packed.bytes.get(start..start.checked_add(packed_size)?)?;
        let mut data = lzma::decompress(source, &LZMA_PROPERTIES, size)?;
        (data.len() == size).then_some(())?;
        if let Some(span) = filter_span {
            undo_call_filter(&mut data, span);
        }

        image.get_mut(range.clone())?.copy_from_slice(&data);
        written.push(range);
        at = start.checked_add(packed_size)?;
        if filter_span.is_some() {
            return Some(at);
        }
    }

    None
}

fn undo_call_filter(data: &mut [u8], span: usize) {
    let limit = span.min(data.len());
    let mut at = 0;

    while at + CALL_FILTER_SPAN <= limit {
        if matches!(data[at], CALL | JUMP) {
            let stored =
                u32::from_be_bytes([data[at + 1], data[at + 2], data[at + 3], data[at + 4]]);
            let relative = stored.wrapping_sub(at as u32 + 1);
            data[at + 1..at + CALL_FILTER_SPAN].copy_from_slice(&relative.to_le_bytes());
            at += CALL_FILTER_SPAN;
        } else {
            at += 1;
        }
    }
}

fn decode_10(packed: &Packed<'_>, table: usize) -> Option<Decoded> {
    let count = usize::from(*packed.bytes.get(table)?);
    (1..=MAX_STREAMS).contains(&count).then_some(())?;

    let mut source = packed.address(table.checked_add(SOURCE_10)?)?;
    let mut image = packed.bytes.to_vec();
    image.get_mut(packed.image.clone())?.fill(0);
    let mut written = Vec::with_capacity(count);

    for index in 0..count {
        let destination = packed.address(table.checked_add(STREAMS_10)?.checked_add(index * 4)?)?;
        let mut tags = ByteTags::new(packed.bytes.get(source..)?);
        let limit = image.len().checked_sub(destination)?;
        let decoded = aplib::decompress(&mut tags, limit, aplib::Variant::Classic)?;
        source = source.checked_add(tags.position())?; // the next stream starts on the following byte

        let range = destination..destination.checked_add(decoded.len())?;
        image.get_mut(range.clone())?.copy_from_slice(&decoded);
        written.push(range);
    }

    let stage = packed.address(table.checked_add(STREAMS_10)?.checked_add(count * 4)?)?;
    (*image.get(stage)? == 0xBE).then_some(())?;
    let imports =
        (read_u32(&image, stage.checked_add(1)?).ok()? as usize).checked_sub(packed.base)?;
    let entry = (read_u32(&image, imports.checked_add(ENTRY_10)?).ok()? as usize)
        .checked_sub(packed.base)?;
    packed.image.contains(&entry).then_some(())?;

    Some(Decoded {
        kind: Kind::Ten,
        image,
        entry,
        written,
        imports,
        beneath_imports: None,
    })
}

fn forward_imports(image: &[u8], mut at: usize, base: usize) -> Option<ListedImports> {
    let start = at;
    let mut modules = Vec::new();
    let mut budget = MAX_THUNKS;

    for _ in 0..MAX_IMPORT_DESCRIPTORS {
        let iat = (read_u32(image, at).ok()? as usize).checked_sub(base)?;
        let (module, next) = read_c_string(image, at.checked_add(4)?)?;
        at = next;

        let mut functions = Vec::new();
        loop {
            budget = budget.checked_sub(1)?;
            let value = u32::from_be_bytes(image.get(at..at.checked_add(4)?)?.try_into().ok()?);
            if value == NEXT_MODULE {
                at = at.checked_add(4)?;
                break;
            }

            if *image.get(at)? >= NAME_ENTRY {
                let name_start = at.checked_add(1)?;
                if *image.get(name_start)? == 0 {
                    modules.push(ModuleImports {
                        module,
                        first_thunk: u32::try_from(iat).ok()?,
                        functions,
                    });
                    return Some(ListedImports {
                        modules,
                        end_markers: Vec::new(),
                        written: start..name_start.checked_add(1)?,
                        names_end: 0,
                    }); // an empty name makes GetProcAddress fail, which ends the list
                }

                let (name, next) = read_c_string(image, name_start)?;
                functions.push(ImportedFunction::Name(name));
                at = next;
                continue;
            }

            at = at.checked_add(4)?;
            let ordinal = u16::try_from(value.checked_add(1)?).ok()?; // stored minus one
            functions.push(ImportedFunction::Ordinal(ordinal));
        }

        modules.push(ModuleImports {
            module,
            first_thunk: u32::try_from(iat).ok()?,
            functions,
        });
    }

    None
}

fn backward_imports(image: &[u8], table: usize, base: usize) -> Option<ListedImports> {
    let mut slot = (read_u32(image, table).ok()? as usize).checked_sub(base)?; // one slot before the first iat
    let mut modules: Vec<ModuleImports> = Vec::new();
    let mut cursor = table.checked_sub(BACKWARD_REWIND)?;

    for _ in 0..MAX_BACKWARD_BYTES {
        cursor = cursor.checked_sub(BACKWARD_STEP)?;
        let marker = *image.get(cursor)?;
        cursor = cursor.checked_add(1)?; // the stub walks back two and reads one forward

        let function = match marker {
            BACKWARD_END => {
                return (!modules.is_empty()).then_some(ListedImports {
                    modules,
                    end_markers: Vec::new(),
                    written: 0..0,
                    names_end: 0,
                });
            }
            BACKWARD_ORDINAL => {
                let ordinal = read_u32(image, cursor).ok()?;
                ImportedFunction::Ordinal(u16::try_from(ordinal).ok()?)
            }
            0 if is_module_name(image, cursor) => {
                slot = slot.checked_add(THUNK_SIZE)?; // the stub knows a dll by LoadLibraryA succeeding
                modules.push(ModuleImports {
                    module: read_c_string(image, cursor)?.0,
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

fn unpack_encrypted(image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
    let model = image.model();
    let decryptor = find_pattern(image.bytes(), DECRYPT_5)?;
    let packed = Packed {
        bytes: image.bytes(),
        base: origin.base,
        image: 0..image.bytes().len(),
    };
    let Encrypted {
        range,
        entry,
        section,
        stock,
    } = find_encrypted(&packed, model)?;

    let keys = KEY_OFFSETS.map(|offset| image.bytes().get(decryptor + offset).copied());
    let [Some(left), Some(add), Some(right)] = keys else {
        return None;
    };
    let decrypt = |byte: u8| {
        byte.rotate_left(u32::from(left) % 8)
            .wrapping_add(add)
            .rotate_right(u32::from(right) % 8)
    };

    let file = origin
        .read_file()
        .and_then(|file| mapped_file(&file, image));
    let pristine = file.and_then(|mut file| {
        file.get_mut(range.clone())?
            .iter_mut()
            .for_each(|byte| *byte = decrypt(*byte));
        Some(file)
    });
    let finished = match &pristine {
        Some(pristine) => image.bytes().get(range.clone()) == pristine.get(range.clone()), // the stub decrypts in place, so a match with the decrypted file means it ran
        None => loader_ran(image.bytes(), model),
    };

    let mut restored = image.bytes().to_vec();
    let version = if stock { "5" } else { MODIFIED_5 };
    let mut report = PackerReport::new(NAME, Some(version.to_owned()));
    if !finished {
        let (code, source) = match &pristine {
            Some(pristine) => (
                pristine.get(range.clone())?.to_vec(),
                "code from the packed file",
            ),
            None => {
                let encrypted = image.bytes().get(range.clone())?;
                let code = encrypted.iter().map(|byte| decrypt(*byte)).collect();
                (code, "code decrypted in memory")
            }
        };
        restored.get_mut(range.clone())?.copy_from_slice(&code);
        report.restored.push(source);
    }

    write_u32(
        &mut restored,
        model.entry_point_offset,
        u32::try_from(entry).ok()?,
    )
    .ok()?;
    report.restored.push("entry point");

    let imports = model
        .directory(&restored, IMPORT_DIRECTORY)
        .ok()
        .flatten()
        .and_then(|directory| {
            let memory = image.bytes();
            imports_from_original(
                &mut restored,
                model,
                directory.rva().as_usize(),
                &mut &memory[..],
            )
        }); // mew 5 leaves the import table alone
    if imports.is_some() {
        report.restored.push("imports");
    }

    let flags_at = section
        .header_offset
        .checked_add(SECTION_CHARACTERISTICS_OFFSET)?;
    let flags = read_u32(&restored, flags_at).ok()?;
    write_u32(&mut restored, flags_at, flags & !WRITABLE).ok()?; // the stub needs to write its code once
    report.restored.push("section flags");
    parse_memory_image(&restored).ok()?;

    let fresh = pristine.filter(|_| finished).and_then(|pristine| {
        fresh_image(
            image.bytes(),
            &restored,
            &pristine,
            origin.base,
            origin.base,
            image.bytes().len(),
            &[],
        )
    });

    Some(Unpacked {
        image: Some(restored),
        findings: PackerFindings {
            report,
            imports: imports.unwrap_or(PackerImports::Unknown),
        },
        fresh,
    })
}

fn loader_ran(memory: &[u8], model: &PeModel) -> bool {
    model
        .directory(memory, IMPORT_DIRECTORY)
        .ok()
        .flatten()
        .and_then(|directory| {
            let descriptor = directory.rva().as_usize();
            read_u32(memory, descriptor.checked_add(IMPORT_IAT_OFFSET)?).ok()
        })
        .and_then(|iat| read_u32(memory, iat as usize).ok())
        .is_none_or(|slot| slot >= model.image_size) // the loader swaps lookup entries inside the image for addresses in a dll
}

fn find_encrypted<'a>(packed: &Packed<'_>, model: &'a PeModel) -> Option<Encrypted<'a>> {
    (0..packed.bytes.len())
        .filter_map(|at| register_load(packed.bytes, at))
        .filter(|load| load.register == ESI)
        .find_map(|load| {
            let table = load.value.checked_sub(packed.base)?;
            let count = read_u32(packed.bytes, table).ok()? as usize;
            let entry = packed.address(table.checked_add(TABLE_ENTRY_5)?)?;
            let start = packed.address(table.checked_add(TABLE_START_5)?)?;
            let last = start.checked_add(count.checked_sub(1)?)?;

            let mapped = |rva: usize, section: &SectionModel| {
                u32::try_from(rva).is_ok_and(|rva| section.contains_rva(Rva(rva)))
            };
            let encrypted = model
                .sections()
                .iter()
                .find(|section| section.virtual_address().as_usize() == start)?;
            let entry_mapped = model
                .sections()
                .iter()
                .any(|section| mapped(entry, section));
            (mapped(last, encrypted) && entry_mapped).then_some(())?;

            Some(Encrypted {
                range: start..last + 1,
                entry,
                section: encrypted,
                stock: pattern_at(packed.bytes, load.at, STUB_5),
            })
        })
}
