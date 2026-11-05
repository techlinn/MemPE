use std::ops::Range;

use super::codecs::aplib;
use super::codecs::bitstream::ByteTags;
use super::tables::{
    DEBUG_ADDRESS_OFFSET, DEBUG_ENTRY_SIZE, DEBUG_SIZE_OFFSET, LinkerBounds,
    MAX_IMPORT_DESCRIPTORS, MAX_THUNKS, RESOURCE_DATA_SIZE_OFFSET, ResourceLayout, Restoration,
    SectionHints, SectionPiece, THUNK_SIZE, apply_listed_imports, clear_directory, debug_timestamp,
    fresh_image, iat_span, lay_out_resources, linker_bounds, lowest_moved_leaf, map_disk_image,
    name_sections, pogo_parts, pogo_sections, pogo_tls_directory, read_c_string,
    recover_directories, relocations_intact, repair_icon_groups, replace_first_section,
    resource_layout, restore_moved_resources, restore_tls, security_cookie, split_merged_section,
    walk_resources,
};
use super::{
    ImportedFunction, ModuleImports, Origin, PackerFindings, PackerImports, PackerReport, Unpacked,
    find_pattern, find_patterns,
};
use crate::pe::image::{read_u16, read_u32, write_u32};
use crate::pe::parse::{parse_disk_image, parse_memory_image};
use crate::pe::{
    BASERELOC_DIRECTORY, BOUND_IMPORT_DIRECTORY, DEBUG_DIRECTORY, DELAY_IMPORT_DIRECTORY,
    DYNAMIC_BASE, LOAD_CONFIG_DIRECTORY, PeImage, PeKind, PeModel, RESOURCE_DIRECTORY,
};

const NAME: &str = "FSG";
const TIMESTAMP_OFFSET: usize = 8;
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
const EBX: u8 = 3;
const ESI: u8 = 6;
const EDI: u8 = 7;
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

struct StubImports {
    modules: Vec<ModuleImports>,
    end_markers: Vec<usize>,
    blob: Range<usize>,
    names_end: usize,
}

struct Evidence<'a> {
    memory: &'a [u8],
    original: &'a [u8],
    finished: bool,
    stub_writes: [Range<usize>; 2],
    constants_start: Option<usize>,
    names_end: usize,
}

impl Evidence<'_> {
    fn untouched(&self, range: Range<usize>) -> bool {
        !self.finished
            || range.into_iter().all(|at| {
                self.stub_writes.iter().any(|written| written.contains(&at))
                    || self.memory.get(at) == self.original.get(at)
            })
    }
}

struct Load {
    at: usize,
    register: u8,
    value: usize,
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
    let start = first.virtual_address().as_usize();
    let end = start.checked_add(first.span() as usize)?;
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

    let version = Some(stub.version.to_owned());
    restore(image, origin, stub, &decoded, start..end, version)
}

fn restore(
    image: &PeImage<'_>,
    origin: &Origin<'_>,
    stub: &Stub,
    decoded: &Decoded,
    image_range: Range<usize>,
    version: Option<String>,
) -> Option<Unpacked> {
    let original = decoded.image.as_slice();
    let model = image.model();
    let end = image_range.end;
    let mut restored = image.bytes().to_vec();
    let mut report = PackerReport::new(NAME, version);

    let listed = listed_imports(original, &stub.imports, origin.base);
    let layout = resource_layout(
        image.bytes(),
        model,
        listed
            .iter()
            .flat_map(|listed| &listed.modules)
            .map(|module| module.module.as_str()),
    );
    let finished = listed
        .as_ref()
        .is_some_and(|listed| stub_finished(image.bytes(), original, &listed.modules));
    if !finished {
        restored
            .get_mut(image_range.clone())?
            .copy_from_slice(original.get(image_range.clone())?);
        report.restored.push("code and data from the packed data");
    }
    let iat = listed.as_ref().and_then(|listed| {
        iat_span(
            listed
                .modules
                .iter()
                .map(|module| (module.first_thunk as usize, module.functions.len())),
            THUNK_SIZE,
        )
        .map(|(start, size)| start..start + size)
    });
    let evidence = Evidence {
        memory: image.bytes(),
        original,
        finished,
        stub_writes: [
            iat.clone().unwrap_or_default(),
            listed
                .as_ref()
                .map(|listed| listed.blob.clone())
                .unwrap_or_default(),
        ],
        constants_start: iat.as_ref().map(|iat| iat.start),
        names_end: listed.as_ref().map_or(0, |listed| listed.names_end),
    };

    write_u32(
        &mut restored,
        model.entry_point_offset,
        u32::try_from(stub.entry).ok()?,
    )
    .ok()?;
    report.restored.push("entry point");

    let imports = listed.and_then(
        |StubImports {
             modules,
             end_markers,
             ..
         }| {
            for slot in end_markers {
                write_u32(&mut restored, slot, 0).ok()?;
            }
            apply_listed_imports(&mut restored, model, modules)
        },
    );
    match imports {
        Some(_) => report.restored.push("imports"),
        None => report.unrestored.push("imports"),
    }
    if let Some((at, beneath)) = &decoded.beneath_imports {
        restored
            .get_mut(*at..at.checked_add(beneath.len())?)?
            .copy_from_slice(beneath); // 1.x decodes its import list over the original import table
    }

    let image_end = match stub.imports {
        ImportData::Pairs { .. } => end.checked_sub(SLACK_2_0)?,
        ImportData::Blob { .. } => end,
    };
    let moved = lowest_moved_leaf(&restored, model, end);
    let kept_in_packer = match moved {
        Some(_) => None,
        None => resources_at_image_end(&mut restored, model, image_end, layout, original),
    };
    let resources = moved.or(kept_in_packer);
    let pogo = pogo_parts(&restored, model, end);
    let linker_pieces = pogo
        .as_deref()
        .and_then(|parts| pogo_sections(parts, model, end, Some(stub.entry)));
    let from_linker = linker_pieces.is_some();
    let bounds = linker_bounds(&restored, model, stub.entry);
    let pieces = linker_pieces.or_else(|| stream_sections(stub, &evidence, bounds, resources, end));
    let ranges: Vec<Range<usize>> = match &pieces {
        Some(pieces) => pieces.iter().map(|piece| piece.start..piece.end).collect(),
        None => resources.into_iter().map(|leaf| leaf..image_end).collect(), // 2.0 packs the leaves from where .rsrc began
    };
    let resources_restored = match kept_in_packer {
        Some(_) => Restoration::Restored,
        None => restore_moved_resources(&mut restored, model, &ranges, end, layout, Some(original)),
    };
    report.record("resources", resources_restored);
    if has_blank_leaf(&restored, model) {
        report.lost.push("resource data the packer blanked"); // 2.0 zeroes delphi's DVCLAL and PACKAGEINFO
    }
    let icons = repair_icon_groups(&mut restored, model);
    report.record("icon groups the packer overwrote", icons); // 1.x writes the next leaf into a group's tail

    let tls = restore_tls(
        &mut restored,
        model,
        origin.base,
        end,
        pogo.as_deref().and_then(pogo_tls_directory),
    );
    report.record("original TLS directory", tls);
    recover_directories(&mut restored, model, origin.base, end, &mut report);
    if let Some(timestamp) = debug_timestamp(&restored, model) {
        let at = model.nt_offset.checked_add(TIMESTAMP_OFFSET)?;
        if read_u32(&restored, at).ok() != Some(timestamp) {
            write_u32(&mut restored, at, timestamp).ok()?;
            report.restored.push("build timestamp");
        }
    }
    let relocations = check_relocations(&mut restored, model, end);
    report.record("relocations", relocations);

    let sections = match pieces {
        Some(pieces) => replace_first_section(&mut restored, model, &pieces),
        None => split_merged(
            &mut restored,
            model,
            origin.base,
            stub,
            &evidence,
            resources,
            image_end,
        ),
    };
    match (sections.is_some(), from_linker) {
        (true, true) => report.restored.push("section table"),
        (true, false) => {
            report.restored.push("code and data sections");
            report.lost.push("section table");
        }
        (false, _) => report.lost.push("section table"),
    }

    clear_directory(&mut restored, model, BOUND_IMPORT_DIRECTORY);
    parse_memory_image(&restored).ok()?;

    let fresh = finished
        .then(|| {
            fresh_image(
                image.bytes(),
                &restored,
                original,
                origin.base,
                origin.base,
                end,
                &[],
            )
        })
        .flatten();

    Some(Unpacked {
        image: Some(restored),
        findings: PackerFindings {
            report,
            imports: imports.unwrap_or(PackerImports::Unknown),
        },
        fresh,
    })
}

fn resources_at_image_end(
    restored: &mut [u8],
    model: &PeModel,
    image_end: usize,
    layout: ResourceLayout,
    pristine: &[u8],
) -> Option<usize> {
    let relocatable = model.is_dll
        || read_u16(restored, model.dll_characteristics_offset)
            .is_ok_and(|flags| flags & DYNAMIC_BASE != 0);
    (!relocatable).then_some(())?; // its .reloc would follow .rsrc
    let root = model
        .directory(restored, RESOURCE_DIRECTORY)
        .ok()??
        .rva()
        .as_usize();
    (root >= image_end).then_some(())?;
    let first = model.sections().first()?.virtual_address().as_usize();
    let page = model.section_alignment as usize;
    let mut start = image_end;

    while start > first {
        start = start.checked_sub(page)?;
        restored
            .get(start..start.checked_add(page)?)?
            .iter()
            .all(|byte| *byte == 0)
            .then_some(())?;
        if lay_out_resources(
            restored,
            model,
            root,
            start..image_end,
            layout,
            Some(pristine),
        )
        .is_some()
        {
            return Some(start);
        }
    }
    None
}

fn has_blank_leaf(restored: &[u8], model: &PeModel) -> bool {
    let Some(root) = model
        .directory(restored, RESOURCE_DIRECTORY)
        .ok()
        .flatten()
        .map(|directory| directory.rva().as_usize())
    else {
        return false;
    };
    walk_resources(restored, root).is_some_and(|tree| {
        tree.data_entries.iter().any(|entry| {
            let leaf = |offset: usize| {
                read_u32(restored, root.checked_add(*entry)?.checked_add(offset)?)
                    .ok()
                    .map(|value| value as usize)
            };
            let data = leaf(0)
                .zip(leaf(RESOURCE_DATA_SIZE_OFFSET))
                .and_then(|(rva, size)| restored.get(rva..rva.checked_add(size)?));
            data.is_some_and(|data| !data.is_empty() && data.iter().all(|byte| *byte == 0))
        })
    })
}

fn stream_sections(
    stub: &Stub,
    evidence: &Evidence<'_>,
    bounds: Option<LinkerBounds>,
    resources: Option<usize>,
    end: usize,
) -> Option<Vec<SectionPiece>> {
    let ImportData::Blob { at, .. } = stub.imports else {
        return None;
    };
    let starts: Vec<usize> = stub
        .streams
        .iter()
        .map(|stream| stream.destination)
        .filter(|destination| *destination != at) // the import data is not a section
        .chain(
            bounds
                .into_iter()
                .flat_map(|bounds| [Some(bounds.code_end), bounds.data])
                .flatten(),
        )
        .collect(); // one stream covers sections whose raw data ran on without a gap
    let constants = evidence.constants_start.filter(|iat| {
        let piece_start = starts.iter().copied().filter(|start| start <= iat).max();
        let piece_end = starts
            .iter()
            .copied()
            .filter(|start| start > iat)
            .min()
            .unwrap_or(end);
        piece_start.is_some_and(|piece_start| evidence.untouched(piece_start..piece_end))
    });
    let hints = SectionHints {
        code: Some(stub.entry),
        code_end: bounds.map(|bounds| bounds.code_end),
        constants,
        relocations: None,
        resources,
    };
    Some(name_sections(starts, end, &hints))
}

fn split_merged(
    restored: &mut [u8],
    model: &PeModel,
    base: usize,
    stub: &Stub,
    evidence: &Evidence<'_>,
    resources: Option<usize>,
    image_end: usize,
) -> Option<()> {
    let page = model.section_alignment as usize;
    let constants_end = read_only_end(restored, model).max(evidence.names_end);
    let constants_page = constants_end.checked_next_multiple_of(page);
    let data = match security_cookie(restored, model, base) {
        Some(cookie) => constants_page.map(|constants| constants.min(cookie / page * page)), // msvc puts it on the first page of .data
        None => constants_page,
    };
    let split = evidence
        .constants_start
        .zip(data)
        .filter(|(constants, data)| constants < data && evidence.untouched(*constants..*data));
    let hints = SectionHints {
        code: Some(stub.entry),
        code_end: None,
        constants: split.map(|(constants, _)| constants),
        relocations: None,
        resources,
    };
    split_merged_section(
        restored,
        model,
        &hints,
        split.map(|(_, data)| data),
        Some(image_end),
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

fn register_load(bytes: &[u8], at: usize) -> Option<Load> {
    let code = bytes.get(at..)?;
    let immediate = |offset: usize| read_u32(code, offset).ok().map(|value| value as usize);
    let (register, value) = match *code.first()? {
        opcode @ 0xB8..=0xBF => (opcode - 0xB8, immediate(1)?),
        0x68 => match *code.get(5)? {
            pop @ 0x58..=0x5F => (pop - 0x58, immediate(1)?),
            _ => return None,
        },
        0x8D => {
            let modrm = *code.get(1)?;
            (modrm & 0xC7 == 0x05).then_some(((modrm >> 3) & 7, immediate(2)?))?
        }
        0xC7 => {
            let modrm = *code.get(1)?;
            (modrm & 0xF8 == 0xC0).then_some((modrm & 7, immediate(2)?))?
        }
        _ => return None,
    };
    Some(Load {
        at,
        register,
        value,
    })
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
    let version = match stock_at(scan.bytes, at, STUB_2_0) {
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

    let version = match stock_at(scan.bytes, load.at, STUB_1_33) {
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
    if stock_at(bytes, start, STUB_1_31) {
        return "1.31";
    }
    if !stock_at(bytes, start, STUB_1_0) {
        return MODIFIED_1_X;
    }
    let tail = bytes
        .get(start.saturating_add(STUB_1_0_LENGTH)..)
        .unwrap_or_default();
    STUB_1_0_TAILS
        .iter()
        .find(|(pattern, _)| find_pattern(tail, pattern) == Some(0))
        .map_or("1.x", |(_, version)| version)
}

fn stock_at(bytes: &[u8], at: usize, pattern: &str) -> bool {
    bytes
        .get(at..)
        .is_some_and(|code| find_pattern(code, pattern) == Some(0))
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

fn mapped_file(file: &[u8], image: &PeImage<'_>) -> Option<Vec<u8>> {
    let disk = parse_disk_image(file).ok()?;
    let model = disk.model();
    let memory = image.model();
    let same_image = model.image_size == memory.image_size
        && read_u32(file, model.entry_point_offset).ok()
            == read_u32(image.bytes(), memory.entry_point_offset).ok();
    same_image.then_some(())?;
    map_disk_image(file, model.image_size as usize)
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

fn listed_imports(original: &[u8], imports: &ImportData, base: usize) -> Option<StubImports> {
    match imports {
        ImportData::Blob { at, scheme } => {
            let (modules, end) = blob_imports(original, *at, scheme, base)?;
            Some(StubImports {
                modules,
                end_markers: Vec::new(),
                blob: *at..end,
                names_end: end,
            })
        }
        ImportData::Pairs { list } => {
            let (modules, end_markers, names_end) = paired_imports(original, *list, base)?;
            Some(StubImports {
                modules,
                end_markers,
                blob: 0..0,
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

fn read_only_end(restored: &[u8], model: &PeModel) -> usize {
    let directory_end = |index: usize| {
        let directory = model.directory(restored, index).ok().flatten()?;
        directory
            .rva()
            .as_usize()
            .checked_add(directory.size() as usize)
    };
    let debug_data_end = model
        .directory(restored, DEBUG_DIRECTORY)
        .ok()
        .flatten()
        .map_or(0, |directory| {
            let start = directory.rva().as_usize();
            (0..directory.size() as usize / DEBUG_ENTRY_SIZE)
                .filter_map(|index| {
                    let entry = start.checked_add(index.checked_mul(DEBUG_ENTRY_SIZE)?)?;
                    let size = read_u32(restored, entry.checked_add(DEBUG_SIZE_OFFSET)?).ok()?;
                    let rva = read_u32(restored, entry.checked_add(DEBUG_ADDRESS_OFFSET)?).ok()?;
                    (rva as usize).checked_add(size as usize)
                })
                .max()
                .unwrap_or(0)
        });
    [
        LOAD_CONFIG_DIRECTORY,
        DEBUG_DIRECTORY,
        DELAY_IMPORT_DIRECTORY,
    ]
    .into_iter()
    .filter_map(directory_end)
    .chain([debug_data_end])
    .max()
    .unwrap_or(0)
}

fn stub_finished(memory: &[u8], original: &[u8], modules: &[ModuleImports]) -> bool {
    modules
        .iter()
        .rev()
        .find(|module| !module.functions.is_empty())
        .is_some_and(|module| {
            let slot = module.first_thunk as usize;
            let filled = read_u32(memory, slot).ok();
            filled.is_some_and(|value| value != 0) && filled != read_u32(original, slot).ok()
        }) // the stub fills the last module's iat right before it jumps
}

fn check_relocations(restored: &mut [u8], model: &PeModel, end: usize) -> Restoration {
    let directory = model
        .directory(restored, BASERELOC_DIRECTORY)
        .ok()
        .flatten();
    let intact = directory.is_some_and(|directory| {
        let start = directory.rva().as_usize();
        start < end && relocations_intact(restored, start, directory.size() as usize)
    });
    if intact {
        return Restoration::Absent;
    }

    clear_directory(restored, model, BASERELOC_DIRECTORY);
    let dynamic = read_u16(restored, model.dll_characteristics_offset)
        .is_ok_and(|flags| flags & DYNAMIC_BASE != 0);
    match dynamic {
        true => Restoration::Lost,
        false => Restoration::Absent,
    }
}
