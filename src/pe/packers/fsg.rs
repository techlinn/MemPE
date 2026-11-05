use std::ops::Range;

use super::codecs::aplib;
use super::codecs::bitstream::ByteTags;
use super::streamed::{
    EBX, EDI, ESI, ListedImports, Load, StreamedImage, mapped_file, register_load, restore,
};
use super::tables::{
    MAX_IMPORT_DESCRIPTORS, MAX_THUNKS, THUNK_SIZE, first_section_range, read_c_string,
};
use super::{ImportedFunction, ModuleImports, Origin, Unpacked, find_patterns, pattern_at};
use crate::pe::image::{read_u16, read_u32};
use crate::pe::{PeImage, PeKind};

const NAME: &str = "FSG";
const STUB_2_0: &str = "87 25 ?? ?? ?? ?? 61 94 55 A4 B6 80 FF 13";
const STUB_1_33: &str = "BE ?? ?? ?? ?? AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13";
const STUB_1_31: &str =
    "BB ?? ?? ?? ?? BF ?? ?? ?? ?? BE ?? ?? ?? ?? 53 BB ?? ?? ?? ?? B2 80 A4 B6 80 FF D3";
const STUB_1_0: &str =
    "BB ?? ?? ?? ?? BF ?? ?? ?? ?? BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3";
const STUB_1_0_TAILS: [(&str, &str); 3] = [
    ("FC B2 80", "1.0"),
    ("B2 80 33 DB", "1.1 or 1.2"), // only visible once their decryptor ran
    ("B2 80 A4", "1.3"),
];
const STUB_1_0_LENGTH: usize = 31;
const MODIFIED_2_0: &str = "2.0 (modified stub)";
const MODIFIED_1_33: &str = "1.33 (modified stub)";
const MODIFIED_1_X: &str = "1.x (modified stub)";
const XCHG_ESP: &str = "87 25";
const FRAME_OPERAND: usize = 2;
const LOAD_WINDOW: usize = 0x40;
const MAX_CANDIDATES: usize = 32;
const MAX_ANCHORS: usize = 256;
const FRAME_OFFSET: usize = 0x1C; // the operand is the eax slot of a popad frame
const FRAME_SOURCE: usize = 4;
const FRAME_IMPORTS: usize = 8;
const TABLE_ENTRY: usize = 0x10; // original entry point in the 2.0 pointer table
const SUPPORT_FIRST: usize = 4;
const SUPPORT_SOURCE: usize = 8;
const SUPPORT_STREAMS: usize = 12;
const WORDS_END: u16 = 2;
const WORDS_IMPORTS: u16 = 1;
const WORDS_FIRST_PAGE: u16 = 2; // a page number is stored plus two, so 1 and 2 stay free as markers
const PAGE_SHIFT: u32 = 12;
const SLACK_2_0: usize = 0x1000; // 2.0 makes the empty section one page longer than the image
const DWORDS_END: u32 = 1;
const DWORDS_IMPORTS: u32 = 0;
const MAX_STREAMS: usize = 256;
const OEP_JUMP: &str = "FE ?? 0F 84";
const OEP_JUMP_END: usize = 8;
const OEP_SEARCH: usize = 0x400;
const DEC_OPCODE: u8 = 0x08;
const OPCODE_BITS: u8 = 0x38;
const NEXT_MODULE: u32 = 0x7FFF_FFFF; // at or above ends a module, all ones ends the list
const ORDINAL_LIMIT: u32 = 0x1_0000;
const OLD_SCHEME: Scheme = Scheme {
    module: 1,
    ordinal: 2,
    end: 3,
    name_shift: 3,
};
const SCHEME_1_33: Scheme = Scheme {
    module: 1,
    ordinal: 0,
    end: 2,
    name_shift: 2,
};

struct Scheme {
    module: u8,
    ordinal: u8,
    end: u8,
    name_shift: u8, // the stub decrements markers and first letters to zero
}

enum ImportData {
    Blob { at: usize, scheme: &'static Scheme },
    Pairs { list: usize },
}

struct Decoded {
    image: Vec<u8>,
    beneath_imports: Option<(usize, Vec<u8>)>,
}

struct Stream {
    destination: usize,
    source: Option<usize>, // none continues after the previous stream
    imports: bool,
}

struct Stub {
    version: &'static str,
    entry: usize,
    streams: Vec<Stream>,
    imports: ImportData,
}

pub(super) fn unpack(image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
    let model = image.model();
    (model.kind() == PeKind::Pe32).then_some(())?;
    let first = model.sections().first()?;
    (first.raw_size == 0).then_some(())?;

    let Range { start, end } = first_section_range(model)?;

    let stubs = find_stubs(image.bytes(), origin.base, &(start..end));
    let first_version = stubs.first()?.version;

    let decode = |packed: &[u8]| {
        stubs.iter().find_map(|stub| {
            original_image(stub, packed, start..end).map(|decoded| (stub, decoded))
        })
    };
    let decoded = decode(image.bytes()).or_else(|| {
        let file = origin.read_file()?;
        decode(&mapped_file(&file, image)?)
    }); // fsg never overwrites its packed data
    let Some((stub, decoded)) = decoded else {
        return Some(Unpacked::detected_only(
            NAME,
            Some(first_version.to_owned()),
            "image (its packed data could not be decoded)",
        ));
    };

    let image_end = match stub.imports {
        ImportData::Pairs { .. } => end.checked_sub(SLACK_2_0)?,
        ImportData::Blob { .. } => end,
    };
    let section_starts = match stub.imports {
        ImportData::Blob { at, .. } => Some(
            stub.streams
                .iter()
                .map(|stream| stream.destination)
                .filter(|destination| *destination != at) // the import data is not a section
                .collect(),
        ),
        ImportData::Pairs { .. } => None,
    };
    let imports = listed_imports(&decoded.image, &stub.imports, origin.base);

    restore(
        image,
        origin,
        StreamedImage {
            name: NAME,
            version: stub.version,
            entry: stub.entry,
            image: start..end,
            image_end,
            original: decoded.image,
            beneath_imports: decoded.beneath_imports,
            imports,
            section_starts,
            keeps_code_fields: true,
        },
    )
}

struct Scan<'a> {
    bytes: &'a [u8],
    base: usize,
    image: Range<usize>,
    distant_entry: Option<usize>,
}

impl Scan<'_> {
    fn address(&self, offset: usize) -> Option<usize> {
        (read_u32(self.bytes, offset).ok()? as usize).checked_sub(self.base)
    }

    fn entry(&self, stub: usize) -> Option<usize> {
        let near = stub..stub.saturating_add(OEP_SEARCH).min(self.bytes.len());
        oep_targets(self.bytes, near, &self.image)
            .next()
            .or(self.distant_entry)
    }
}

fn find_stubs(bytes: &[u8], base: usize, image: &Range<usize>) -> Vec<Stub> {
    let outside = [0..image.start, image.end..bytes.len()];
    let scan = Scan {
        bytes,
        base,
        image: image.clone(),
        distant_entry: distant_entry(bytes, &outside, image),
    };
    let mut stubs = Vec::new();

    for area in outside {
        let Some(region) = bytes.get(area.clone()) else {
            continue;
        };
        let loads: Vec<Load> = area
            .clone()
            .filter_map(|at| register_load(bytes, at))
            .filter(|load| {
                matches!(load.register, EBX | ESI | EDI)
                    && load
                        .value
                        .checked_sub(base)
                        .is_some_and(|rva| rva < bytes.len())
            })
            .collect();

        stubs.extend(
            find_patterns(region, XCHG_ESP)
                .take(MAX_ANCHORS)
                .filter_map(|offset| stub_2_0(&scan, area.start.checked_add(offset)?)),
        );
        stubs.extend(
            loads
                .iter()
                .filter(|load| load.register == ESI)
                .take(MAX_ANCHORS)
                .filter_map(|load| stub_1_33(&scan, load)),
        );
        stubs.extend(word_stubs(&scan, &loads));
    }

    stubs.truncate(MAX_CANDIDATES);
    stubs
}

fn stub_2_0(scan: &Scan<'_>, at: usize) -> Option<Stub> {
    let slot = scan.address(at.checked_add(FRAME_OPERAND)?)?;
    let frame = slot.checked_sub(FRAME_OFFSET)?;
    let stream = Stream {
        destination: scan.address(frame)?,
        source: Some(scan.address(frame.checked_add(FRAME_SOURCE)?)?),
        imports: false,
    };

    let list = scan.address(frame.checked_add(FRAME_IMPORTS)?)?;
    let entry = scan.address(slot.checked_add(TABLE_ENTRY)?)?;

    let version = match pattern_at(scan.bytes, at, STUB_2_0) {
        true => "2.0",
        false => MODIFIED_2_0,
    };

    checked(
        Stub {
            version,
            entry,
            streams: vec![stream],
            imports: ImportData::Pairs { list },
        },
        &scan.image,
    )
}

fn stub_1_33(scan: &Scan<'_>, load: &Load) -> Option<Stub> {
    let support = load.value.checked_sub(scan.base)?;
    (scan.address(support.checked_add(SUPPORT_FIRST)?)? == scan.image.start).then_some(())?;

    let mut streams = vec![Stream {
        destination: scan.image.start,
        source: Some(scan.address(support.checked_add(SUPPORT_SOURCE)?)?),
        imports: false,
    }];
    let mut blob = None;
    let mut cursor = support.checked_add(SUPPORT_STREAMS)?;

    for _ in 0..MAX_STREAMS {
        let value = read_u32(scan.bytes, cursor).ok()?;
        cursor = cursor.checked_add(4)?;
        let destination = match value {
            DWORDS_END => break,
            DWORDS_IMPORTS => {
                let destination = scan.address(cursor)?;
                cursor = cursor.checked_add(4)?;
                blob = Some(destination);
                destination
            }
            next => (next as usize).checked_sub(1)?.checked_sub(scan.base)?, // stored plus one so 0 and 1 stay free
        };

        streams.push(Stream {
            destination,
            source: None,
            imports: value == DWORDS_IMPORTS,
        });
    }

    let version = match pattern_at(scan.bytes, load.at, STUB_1_33) {
        true => "1.33",
        false => MODIFIED_1_33,
    };

    checked(
        Stub {
            version,
            entry: scan.entry(load.at)?,
            streams,
            imports: ImportData::Blob {
                at: blob?,
                scheme: &SCHEME_1_33,
            },
        },
        &scan.image,
    )
}

fn word_stubs(scan: &Scan<'_>, loads: &[Load]) -> Vec<Stub> {
    let mut stubs = Vec::new();
    let anchors = loads
        .iter()
        .filter(|load| {
            load.register == EDI && load.value.checked_sub(scan.base) == Some(scan.image.start)
        })
        .take(MAX_ANCHORS);

    for first in anchors {
        for support in near(loads, EBX, first) {
            for source in near(loads, ESI, first) {
                stubs.extend(word_stub(scan, [support, first, source]));
                if stubs.len() >= MAX_CANDIDATES {
                    return stubs;
                }
            }
        }
    }

    stubs
}

fn near<'a>(loads: &'a [Load], register: u8, anchor: &Load) -> impl Iterator<Item = &'a Load> {
    let start = loads.partition_point(|load| load.at.saturating_add(LOAD_WINDOW) < anchor.at);
    let stop = loads.partition_point(|load| load.at <= anchor.at.saturating_add(LOAD_WINDOW));

    loads
        .get(start..stop)
        .unwrap_or_default()
        .iter()
        .filter(move |load| load.register == register)
}

fn word_stub(scan: &Scan<'_>, [support, first, source]: [&Load; 3]) -> Option<Stub> {
    let mut streams = vec![Stream {
        destination: first.value.checked_sub(scan.base)?,
        source: Some(source.value.checked_sub(scan.base)?),
        imports: false,
    }];
    let mut blob = None;
    let mut cursor = support.value.checked_sub(scan.base)?;

    for _ in 0..MAX_STREAMS {
        let word = read_u16(scan.bytes, cursor).ok()?;
        let destination = match word {
            WORDS_END => break,
            WORDS_IMPORTS => {
                let destination = scan.address(cursor.checked_add(2)?)?;
                cursor = cursor.checked_add(6)?;
                blob = Some(destination);
                destination
            }
            page => {
                cursor = cursor.checked_add(2)?;
                (usize::from(page.checked_sub(WORDS_FIRST_PAGE)?) << PAGE_SHIFT)
                    .checked_sub(scan.base)?
            }
        };

        streams.push(Stream {
            destination,
            source: None,
            imports: word == WORDS_IMPORTS,
        });
    }

    let start = support.at.min(first.at).min(source.at);
    checked(
        Stub {
            version: word_version(scan.bytes, start),
            entry: scan.entry(start)?,
            streams,
            imports: ImportData::Blob {
                at: blob?,
                scheme: &OLD_SCHEME,
            },
        },
        &scan.image,
    )
}

fn word_version(bytes: &[u8], start: usize) -> &'static str {
    if pattern_at(bytes, start, STUB_1_31) {
        return "1.31";
    }
    if !pattern_at(bytes, start, STUB_1_0) {
        return MODIFIED_1_X;
    }

    let tail = start.saturating_add(STUB_1_0_LENGTH);
    STUB_1_0_TAILS
        .iter()
        .find(|(pattern, _)| pattern_at(bytes, tail, pattern))
        .map_or("1.x", |(_, version)| version)
}

fn checked(stub: Stub, image: &Range<usize>) -> Option<Stub> {
    let inside = |rva: usize| image.contains(&rva);
    let first = stub.streams.first()?;
    let fits = first.destination == image.start
        && first.source.is_some_and(|source| !inside(source))
        && inside(stub.entry)
        && stub.streams.iter().all(|stream| inside(stream.destination))
        && match stub.imports {
            ImportData::Blob { at, .. } => inside(at),
            ImportData::Pairs { list } => inside(list),
        };

    fits.then_some(stub)
}

fn distant_entry(bytes: &[u8], outside: &[Range<usize>; 2], image: &Range<usize>) -> Option<usize> {
    let mut targets: Vec<usize> = outside
        .iter()
        .flat_map(|area| oep_targets(bytes, area.clone(), image))
        .take(MAX_ANCHORS)
        .collect(); // a modified stub may load its registers far from the rest of its code
    targets.sort_unstable();
    targets.dedup();

    match targets.as_slice() {
        [target] => Some(*target),
        _ => None,
    }
}

fn oep_targets<'a>(
    bytes: &'a [u8],
    area: Range<usize>,
    image: &'a Range<usize>,
) -> impl Iterator<Item = usize> + 'a {
    let code = bytes.get(area.clone()).unwrap_or_default();
    find_patterns(code, OEP_JUMP).filter_map(move |jump| {
        let decrements = code.get(jump.checked_add(1)?)? & OPCODE_BITS == DEC_OPCODE;
        let after = area.start.checked_add(jump)?.checked_add(OEP_JUMP_END)?;
        let distance = read_u32(code, jump.checked_add(4)?).ok()? as i32;
        let target = after.checked_add_signed(distance as isize)?;
        (decrements && image.contains(&target)).then_some(target)
    })
}

fn original_image(stub: &Stub, packed: &[u8], target: Range<usize>) -> Option<Decoded> {
    let mut image = packed.to_vec();
    image.get_mut(target.clone())?.fill(0); // streams only cover initialized data
    let mut beneath_imports = None;
    let mut source = 0;

    for stream in &stub.streams {
        source = stream.source.unwrap_or(source);
        let mut tags = ByteTags::new(packed.get(source..)?);
        let limit = target.end.checked_sub(stream.destination)?;
        let decoded = aplib::decompress(&mut tags, limit, aplib::Variant::Classic)?;

        let written =
            image.get_mut(stream.destination..stream.destination.checked_add(decoded.len())?)?;
        if stream.imports {
            beneath_imports = Some((stream.destination, written.to_vec()));
        }
        written.copy_from_slice(&decoded);
        source = source.checked_add(tags.position())?; // the next stream starts on the following byte
    }

    Some(Decoded {
        image,
        beneath_imports,
    })
}

fn listed_imports(original: &[u8], imports: &ImportData, base: usize) -> Option<ListedImports> {
    match imports {
        ImportData::Blob { at, scheme } => {
            let (modules, end) = blob_imports(original, *at, scheme, base)?;
            Some(ListedImports {
                modules,
                end_markers: Vec::new(),
                written: *at..end,
                names_end: end,
            })
        }
        ImportData::Pairs { list } => {
            let (modules, end_markers, names_end) = paired_imports(original, *list, base)?;
            Some(ListedImports {
                modules,
                end_markers,
                written: 0..0,
                names_end,
            })
        }
    }
}

fn blob_imports(
    original: &[u8],
    mut at: usize,
    scheme: &Scheme,
    base: usize,
) -> Option<(Vec<ModuleImports>, usize)> {
    let mut modules = Vec::new();

    for _ in 0..MAX_IMPORT_DESCRIPTORS {
        let marker = *original.get(at)?;
        if marker == scheme.end {
            return (!modules.is_empty()).then_some((modules, at.checked_add(1)?));
        }
        (marker == scheme.module).then_some(())?;

        let iat = (read_u32(original, at.checked_add(1)?).ok()? as usize).checked_sub(base)?;
        let (module, next) = read_c_string(original, at.checked_add(5)?)?;
        at = next;

        let mut functions = Vec::new();
        for _ in 0..MAX_THUNKS {
            let marker = *original.get(at)?;
            if marker == scheme.module || marker == scheme.end {
                break;
            }

            if marker == scheme.ordinal {
                let ordinal = read_u32(original, at.checked_add(1)?).ok()?;
                functions.push(ImportedFunction::Ordinal(u16::try_from(ordinal).ok()?));
                let padding = original
                    .get(at.checked_add(5)?..)?
                    .iter()
                    .position(|byte| *byte == 0)?;
                at = at.checked_add(5)?.checked_add(padding)?.checked_add(1)?; // the stub skips to the next nul
                continue;
            }

            let (name, next) = read_c_string(original, at)?;
            let mut name = name.into_bytes();
            name[0] = name[0].checked_sub(scheme.name_shift)?;
            functions.push(ImportedFunction::Name(String::from_utf8(name).ok()?));
            at = next;
        }

        modules.push(ModuleImports {
            module,
            first_thunk: u32::try_from(iat).ok()?,
            functions,
        });
    }

    None
}

fn paired_imports(
    original: &[u8],
    mut at: usize,
    base: usize,
) -> Option<(Vec<ModuleImports>, Vec<usize>, usize)> {
    let address = |value: u32| (value as usize).checked_sub(base);
    let mut modules = Vec::new();
    let mut end_markers = Vec::new();
    let mut names_end = 0;
    let mut budget = MAX_THUNKS;

    for _ in 0..MAX_IMPORT_DESCRIPTORS {
        let iat = address(read_u32(original, at).ok()?)?;
        let (module, module_end) = read_c_string(
            original,
            address(read_u32(original, at.checked_add(4)?).ok()?)?,
        )?;
        names_end = names_end.max(module_end);
        at = at.checked_add(8)?;

        let mut functions = Vec::new();
        let mut slot = iat;
        let last = loop {
            let value = read_u32(original, slot).ok()?;
            if value >= NEXT_MODULE {
                end_markers.push(slot);
                break value == u32::MAX;
            }

            let target = value.checked_add(1)?; // each slot holds its name pointer or ordinal minus one
            functions.push(match target {
                0..ORDINAL_LIMIT => ImportedFunction::Ordinal(u16::try_from(target).ok()?),
                _ => {
                    let (name, name_end) = read_c_string(original, address(target)?)?;
                    names_end = names_end.max(name_end);
                    ImportedFunction::Name(name)
                }
            });

            slot = slot.checked_add(THUNK_SIZE)?;
            budget = budget.checked_sub(1)?;
        };

        modules.push(ModuleImports {
            module,
            first_thunk: u32::try_from(iat).ok()?,
            functions,
        });

        if last {
            return Some((modules, end_markers, names_end));
        }
    }

    None
}
