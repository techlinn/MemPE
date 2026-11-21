use std::collections::HashMap;
use std::ops::Range;

use iced_x86::{FlowControl, Mnemonic};

use super::{Packer, resolved_import};
use crate::pe::bytes::{read_u32, relocation_block, relocation_words, write_u16, write_u32};
use crate::pe::parse::parse_disk_image;
use crate::pe::{
    BASERELOC_DIRECTORY, BOUND_IMPORT_DIRECTORY, HINT_SIZE, IAT_DIRECTORY, IMPORT_DESCRIPTOR_SIZE,
    IMPORT_DIRECTORY, MAX_IMPORT_DESCRIPTORS, MAX_IMPORTS, MAX_NAME_LENGTH, PeImage, PeKind,
    PeModel, RELOCATION_BLOCK_HEADER, RESERVED_DIRECTORY, RESOURCE_DIRECTORY, Rva,
    SECTION_CHARACTERISTICS_OFFSET, SECTION_COUNT_OFFSET, SECTION_HEADER_SIZE, SectionModel,
    map_disk_image,
};
use crate::unpack::codecs::aplib;
use crate::unpack::codecs::bitstream::ByteTags;
use crate::unpack::codecs::call_filter::{self, CallFilter, Stored};
use crate::unpack::codecs::lzx::{Tables, decompress};
use crate::unpack::tables::{
    MAX_RELOCATION_BLOCK, ORDINAL_FLAG, OriginalBytes, RELOCATION_BLOCK_SIZE_OFFSET, Restoration,
    Search, THUNK_SIZE, flags_from_names, iat_span, imports_from_original, read_c_string,
    recover_directories, restore_tls, return_moved_leaves, sole, unique,
};
use crate::unpack::x86::branches::decode_at;
use crate::unpack::{
    ImportedFunction, InitialData, ModuleImports, NameHints, Origin, PackerId, PackerImports,
    PackerReport, Part, Refusal, Step, Unpacked, file_base, find_pattern, find_patterns, hex, need,
    pattern_at, with_initial_data,
};

const NAME: PackerId = PackerId::AsPack;
const LEGACY_ENTRIES: [(&str, &str); 8] = [
    (
        hex("60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5"),
        "1.0x",
    ),
    (
        hex("60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD"),
        "1.08",
    ),
    (
        hex("60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ED"),
        "1.08",
    ),
    (hex("60 EB 03 5D FF E5 E8 F8 FF FF FF 81 ED"), "1.08"),
    (hex("60 E8 41 06 00 00 EB 41"), "1.08.04"),
    (hex("60 E8 70 05 00 00 EB 4C"), "2.000"),
    (hex("60 E8 72 05 00 00 EB 4C"), "2.001"),
    (hex("60 E8 72 05 00 00 EB 33 87 DB 90 00"), "2.1"),
];
const STUB_ENTRIES: [&str; 2] = [
    hex("60 E8 02 00 00 00 EB 09 5D 55 81 ED"), // 2.11: its tail decrypts at run time
    hex("60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01"), // 2.12 and later
];
const MAX_ENTRY_HOPS: usize = 16;
const BITS: u32 = 32;
const TAIL: &str = hex("C2 0C 00 68 ?? ?? ?? ?? C3"); // ret 0Ch / push oep / ret
const TAIL_PUSH_OFFSET: usize = 4;
const LEGACY_TAIL: &str = hex("8B 85 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 89 44 24 1C 61 FF E0"); // 1.x: base + entry rva
const LEGACY_TAIL_ENTRY_OFFSET: usize = 2;
const LEGACY_STUB_START: &str = hex("60 E8 00 00 00 00 5D 81 ED");
const IMPORT_LOAD: &str = hex("BE ?? ?? ?? ?? 8B 95 ?? ?? ?? ??"); // mov esi, rva / mov edx, [ebp+base]
const IMPORT_RVA_OFFSET: usize = 1;
const IMPORT_BASE_OFFSET: usize = 7;
const IMPORT_FIELD_LOAD: &str = hex("8B B5 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 03 F2"); // rva in stub data
const IMPORT_FIELD_OFFSET: usize = 2;
const IMPORT_FIELD_BASE_OFFSET: usize = 8;
const LEGACY_IMPORT_LOAD: &str = hex("8B 95 ?? ?? ?? ?? 8B B5 ?? ?? ?? ?? 8B BD ?? ?? ?? ?? 03 F2");
const LEGACY_IMPORT_FIELD_OFFSET: usize = 8;
const LEGACY_IMPORT_BASE_OFFSET: usize = 2;
const RELOCATION_LOAD: &str = hex("C1 E8 10 ?? ?? 8B B5 ?? ?? ?? ??");
const RELOCATION_FIELD_OFFSET: usize = 7;
const BLOCK_LOOP: &str = hex("8D B5 ?? ?? ?? ?? 83 3E 00 0F 84"); // block table walk
const BLOCK_LOOP_OFFSET: usize = 2;
const BLOCK_FLAGS_LOAD: &str = hex("0F B7 47 14 8D 7C 07 F0 8D B5 ?? ?? ?? ??"); // >= 2.2
const BLOCK_FLAGS_OFFSET: usize = 10;
const SHORT_BLOCK_ENTRY: usize = 8; // rva and unpacked size
const FLAGGED_BLOCK_ENTRY: usize = 12; // rva, unpacked size, characteristics
const BLOCK_SIZE_OFFSET: usize = 4;
const BLOCK_CHARACTERISTICS_OFFSET: usize = 8;
const STORED_BLOCK: u32 = 0xFFFF_FEF2; // stored uncompressed
const BLOCK_READ_SLACK: usize = 0x10E; // decoder over-read
const MAX_BLOCKS: usize = 256;
const LENGTH_BASE: &str =
    hex("00 01 02 03 04 05 06 07 08 0A 0C 0E 10 14 18 1C 20 28 30 38 40 50 60 70 80 A0 C0 E0");
const CALL_FILTER: &str = hex("EB 00 80 3E ?? 75 F3"); // jmp +0: marker filter
const CALL_MARKER_OFFSET: usize = 4;
const APLIB_DEPACKER: &str = hex("B2 80 8A 06 46 88 07 47 02 D2 75 05 8A 16 46 12 D2");
const CALL_SIZE: usize = 5;
const POSITION_FILTER_TAIL: usize = 6; // 1.x filter stops this short of the end
const WIPED_RELOCATION: u16 = 0xFFFF; // applied entries wiped
const REPEATED_PATTERN: Refusal =
    Refusal("a stub sequence mempe reads from appears more than once");
const TABLES_DISAGREE: Refusal = Refusal("the stub's two block loops name different tables");

#[derive(Clone, Copy, Eq, PartialEq)]
enum BlockLayout {
    Short,
    Flagged,
}

impl BlockLayout {
    fn entry_size(self) -> usize {
        match self {
            Self::Short => SHORT_BLOCK_ENTRY,
            Self::Flagged => FLAGGED_BLOCK_ENTRY,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum BaseFault {
    Unconfirmed,
    Missing,
    Ambiguous,
}

impl BaseFault {
    fn refusal(self) -> Refusal {
        Refusal(match self {
            Self::Unconfirmed => "the stub keeps no table field that could confirm its base",
            Self::Missing => "no stub base that the stub's own fields agree with",
            Self::Ambiguous => "more than one stub base agrees with the stub's fields",
        })
    }
}

#[derive(Clone, Copy)]
enum StubRelocations {
    Absent,
    At(usize),
    Unreadable,
}

struct ImportLoad {
    rva: Option<u32>,
    field: Option<u32>,
    base_field: u32,
}

struct Stub {
    index: usize,
    block_layout: BlockLayout,
    start: usize,
    first_section: usize,
    entry: u32,
    import_rva: usize,
    relocations: StubRelocations,
    block_table: Option<usize>,
    codec: Option<Codec>,
}

#[derive(Clone, Copy)]
enum Codec {
    Lzx {
        tables: usize,
        call_marker: Option<u8>,
    },
    Aplib,
}

struct ThunkTable {
    start: usize,
    count: usize,
}

struct Block {
    rva: usize,
    size: Option<usize>,
    filtered: bool,
    decoded: Option<Vec<u8>>,
}

struct PackedFile<'a> {
    file: Vec<u8>,
    base: usize,
    disk: PeModel,
    blocks: Vec<Block>,
    codec: Codec,
    tables: &'a [u8],
}

fn unpack(image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
    let model = image.model();

    if !matches!(model.kind, PeKind::Pe32) {
        return None;
    }

    let file = origin.read_file();
    let relocated = origin
        .linked_base()
        .is_some_and(|linked| linked != origin.base);
    let on_disk = |rva: usize| file_u32_at_rva(file.filter(|_| relocated)?, model, rva); // only a moved image changes the field
    let Some((_, stub)) = find_stub(image.bytes(), model, origin.base, &on_disk) else {
        let reason = "mempe can't restore this ASPack release yet";
        return legacy_release(image.bytes(), model)
            .map(|release| Unpacked::detected_only(NAME, Some(release.to_owned()), reason));
    };

    match stub.and_then(|stub| restore(image, &stub, origin)) {
        Ok(unpacked) => Some(unpacked),
        Err(refusal) => Some(Unpacked::refused(NAME, None, refusal)),
    }
}

fn original_code(image: &PeImage<'_>, base: usize) -> Option<Vec<Range<usize>>> {
    let model = image.model();
    let stub = match find_stub(image.bytes(), model, base, &|_| None) {
        Some((index, _)) => index,
        None => entered_stub(image.bytes(), model, base)?, // before the stub ran its own setup
    };
    (stub > 0).then_some(())?;

    Some(
        model
            .sections
            .iter()
            .take(stub)
            .map(|section| section.range())
            .collect(),
    )
}

// the section whose code the entry reaches, when that code opens as an aspack stub does
fn entered_stub(bytes: &[u8], model: &PeModel, base: usize) -> Option<usize> {
    let mut at = read_u32(bytes, model.entry_point_offset).ok()? as usize;
    for _ in 0..MAX_ENTRY_HOPS {
        let insn = decode_at(bytes, base as u64, BITS, (base + at) as u64)?;
        let next = insn.next_ip() as usize - base;
        at = match insn.flow_control() {
            FlowControl::Next if insn.mnemonic() == Mnemonic::Nop => next,
            FlowControl::UnconditionalBranch if insn.is_jmp_short_or_near() => {
                (insn.near_branch_target() as usize).checked_sub(base)?
            }
            FlowControl::ConditionalBranch if insn.near_branch_target() == insn.next_ip() => next, // 1.07b: jnz +0
            _ => break,
        };
    }

    let opens_stub = STUB_ENTRIES
        .iter()
        .chain(LEGACY_ENTRIES.iter().map(|(pattern, _)| pattern))
        .any(|pattern| pattern_at(bytes, at, pattern));
    opens_stub.then_some(())?;

    let at = Rva(u32::try_from(at).ok()?);
    model
        .sections
        .iter()
        .position(|section| section.contains_rva(at))
}

fn legacy_release(bytes: &[u8], model: &PeModel) -> Option<&'static str> {
    let entry = read_u32(bytes, model.entry_point_offset).ok()? as usize;
    let first_section = model.sections.first()?;
    (!first_section.contains_rva(Rva(entry as u32)) && entry != 0).then_some(())?;

    LEGACY_ENTRIES
        .iter()
        .find(|(pattern, _)| pattern_at(bytes, entry, pattern))
        .map(|(_, release)| *release)
}

fn file_u32_at_rva(file: &[u8], model: &PeModel, rva: usize) -> Option<u32> {
    let section = model.sections.iter().find(|section| {
        let start = section.virtual_address().as_usize();
        (start..start.saturating_add(section.raw_size as usize)).contains(&rva)
    })?;
    let offset =
        (section.raw_pointer as usize).checked_add(rva - section.virtual_address().as_usize())?;
    read_u32(file, offset).ok()
}

fn find_stub(
    bytes: &[u8],
    model: &PeModel,
    base: usize,
    on_disk: &dyn Fn(usize) -> Option<u32>,
) -> Option<(usize, Step<Stub>)> {
    let entry = Rva(read_u32(bytes, model.entry_point_offset).ok()?);
    let first_section = model.sections.first()?.virtual_address().as_usize();

    model
        .sections
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(_, section)| {
            section.is_executable()
                || section.contains_rva(entry)
                || starts_legacy_stub(bytes, section)
        }) // <= 2.12: no exec flag
        .find_map(|(index, section)| {
            stub_in_section(bytes, index, section, base, first_section, on_disk)
        })
}

fn starts_legacy_stub(bytes: &[u8], section: &SectionModel) -> bool {
    let start = section.virtual_address().as_usize();
    pattern_at(bytes, start, LEGACY_STUB_START) // prologue restored at run time
}

fn stub_in_section(
    bytes: &[u8],
    index: usize,
    section: &SectionModel,
    base: usize,
    first_section: usize,
    on_disk: &dyn Fn(usize) -> Option<u32>,
) -> Option<(usize, Step<Stub>)> {
    let Range { start, end } = section.range_in(bytes);
    let code = bytes.get(start..end)?;
    let tail = sole(find_patterns(code, TAIL));
    let legacy_tail = sole(find_patterns(code, LEGACY_TAIL));
    if matches!((&tail, &legacy_tail), (Search::None, Search::None)) {
        return None;
    }

    let refused = |refusal: Refusal| (index, Err(refusal));
    let import = match import_load(bytes, code, start)? {
        Ok(import) => import,
        Err(refusal) => return Some(refused(refusal)),
    };

    let read_from = [
        tail,
        legacy_tail,
        sole(find_patterns(code, BLOCK_LOOP)),
        sole(find_patterns(code, BLOCK_FLAGS_LOAD)),
        sole(find_patterns(code, RELOCATION_LOAD)),
    ];
    if read_from
        .iter()
        .any(|found| matches!(found, Search::Several))
    {
        return Some(refused(REPEATED_PATTERN));
    }

    let [tail, legacy_tail, block_loop, block_flags, relocation_load] = read_from.map(Search::one);
    let read = |at: usize| read_u32(bytes, at).ok();
    let displacement = |hit: Option<usize>, offset: usize| -> Option<u32> {
        read(start.checked_add(hit?)?.checked_add(offset)?)
    };

    let block_field = displacement(block_loop, BLOCK_LOOP_OFFSET);
    let flags_field = displacement(block_flags, BLOCK_FLAGS_OFFSET);
    if block_field
        .zip(flags_field)
        .is_some_and(|(walked, flagged)| walked != flagged)
    {
        return Some(refused(TABLES_DISAGREE));
    }

    let base32 = u32::try_from(base).ok()?;
    let program = first_section..start;
    let confirming: Vec<u32> = [import.field, block_field, flags_field]
        .into_iter()
        .flatten()
        .collect();
    let ebp = stub_base(
        bytes,
        start..end,
        base32,
        import.base_field,
        &confirming,
        &program,
        on_disk,
    );
    if ebp == Err(BaseFault::Ambiguous) {
        return Some(refused(BaseFault::Ambiguous.refusal()));
    }

    let field = |displacement: Option<u32>| -> Option<usize> {
        Some(ebp.ok()?.wrapping_add(displacement?) as usize)
    };

    let import_rva = match import.rva {
        Some(rva) => rva as usize,
        None => read(field(import.field)?)? as usize,
    };
    program.contains(&import_rva).then_some(())?;

    let relocation_field = field(displacement(relocation_load, RELOCATION_FIELD_OFFSET));
    let relocations = match relocation_field.and_then(read).map(|rva| rva as usize) {
        Some(0) => StubRelocations::Absent,
        Some(rva) if program.contains(&rva) => StubRelocations::At(rva),
        _ => StubRelocations::Unreadable,
    };

    let legacy_entry = field(displacement(legacy_tail, LEGACY_TAIL_ENTRY_OFFSET));
    let tail = tail.and_then(|at| start.checked_add(at));
    let entry = match stub_entry(bytes, tail, legacy_entry, ebp.err(), base, &program)? {
        Ok(entry) => entry,
        Err(refusal) => return Some(refused(refusal)),
    };
    let flagged = field(flags_field);

    let stub = Stub {
        index,
        block_layout: if flagged.is_some() {
            BlockLayout::Flagged
        } else {
            BlockLayout::Short
        },
        start,
        first_section,
        entry,
        import_rva,
        relocations,
        block_table: field(block_field).or(flagged),
        codec: stub_codec(code, start),
    };
    Some((index, Ok(stub)))
}

fn import_load(bytes: &[u8], code: &[u8], start: usize) -> Option<Step<ImportLoad>> {
    let read = |at: usize| read_u32(bytes, at).ok();
    let forms = [
        (IMPORT_LOAD, IMPORT_RVA_OFFSET, IMPORT_BASE_OFFSET, true),
        (
            IMPORT_FIELD_LOAD,
            IMPORT_FIELD_OFFSET,
            IMPORT_FIELD_BASE_OFFSET,
            false,
        ),
        (
            LEGACY_IMPORT_LOAD,
            LEGACY_IMPORT_FIELD_OFFSET,
            LEGACY_IMPORT_BASE_OFFSET,
            false,
        ),
    ];

    forms
        .into_iter()
        .find_map(|(pattern, value, base, immediate)| {
            let at = match sole(find_patterns(code, pattern)) {
                Search::None => return None,
                Search::Several => return Some(Err(REPEATED_PATTERN)),
                Search::One(at) => start.checked_add(at)?,
            };
            let value = read(at.checked_add(value)?)?;
            let base_field = read(at.checked_add(base)?)?;
            let (rva, field) = if immediate {
                (Some(value), None)
            } else {
                (None, Some(value))
            };

            Some(Ok(ImportLoad {
                rva,
                field,
                base_field,
            }))
        })
}

fn stub_base(
    bytes: &[u8],
    stub: Range<usize>,
    base: u32,
    base_field: u32,
    confirming: &[u32],
    program: &Range<usize>,
    on_disk: &dyn Fn(usize) -> Option<u32>,
) -> Result<u32, BaseFault> {
    if confirming.is_empty() {
        return Err(BaseFault::Unconfirmed);
    }

    let wanted = base.to_le_bytes();
    let confirmed = |ebp: &u32| {
        confirming.iter().all(|field| {
            read_u32(bytes, ebp.wrapping_add(*field) as usize)
                .is_ok_and(|rva| program.contains(&(rva as usize)))
        })
    };
    let fields: Vec<u32> = bytes
        .get(stub.clone())
        .unwrap_or_default()
        .windows(wanted.len())
        .enumerate()
        .filter(|(_, window)| *window == wanted)
        .filter_map(|(at, _)| u32::try_from(stub.start.checked_add(at)?).ok())
        .filter(|at| confirmed(&at.wrapping_sub(base_field)))
        .collect();

    // the stub writes the base it runs at: a copy the file already holds is no such write
    let written: Vec<u32> = fields
        .iter()
        .copied()
        .filter(|at| on_disk(*at as usize).is_some_and(|stored| stored != base))
        .collect();
    let fields = match (fields.len(), written.len()) {
        (2.., 1) => written,
        _ => fields,
    };

    match fields[..] {
        [field] => Ok(field.wrapping_sub(base_field)),
        [] => Err(BaseFault::Missing),
        _ => Err(BaseFault::Ambiguous),
    }
}

fn stub_entry(
    bytes: &[u8],
    tail: Option<usize>,
    legacy_entry: Option<usize>,
    fault: Option<BaseFault>,
    base: usize,
    program: &Range<usize>,
) -> Option<Step<u32>> {
    let read = |at: usize| read_u32(bytes, at).ok();
    let in_original = |rva: usize| program.contains(&rva);

    let entry = match (tail, fault) {
        (_, Some(fault)) => Err(fault.refusal()),
        (Some(tail), None) => {
            let pushed = read(tail.checked_add(TAIL_PUSH_OFFSET)?)? as usize;
            match pushed.checked_sub(base) {
                _ if pushed == 0 => Err(Refusal("the stub had not finished unpacking")), // it writes the entry last
                Some(rva) if rva == 0 || in_original(rva) => Ok(rva), // dll without entry: base
                _ => Err(Refusal(
                    "the entry point the stub pushes is outside the program",
                )),
            }
        }
        (None, None) => {
            let stored = legacy_entry.and_then(read);
            match stored.map(|rva| rva as usize) {
                Some(rva) if rva == 0 || in_original(rva) => Ok(rva),
                Some(_) => Err(Refusal("the stored entry point is outside the program")),
                None => Err(Refusal("the stub's entry point field cannot be read")),
            }
        }
    }
    .and_then(|rva| {
        need(
            u32::try_from(rva).ok(),
            "the entry point does not fit 32 bits",
        )
    });

    Some(entry)
}

fn stub_codec(code: &[u8], start: usize) -> Option<Codec> {
    match sole(find_patterns(code, LENGTH_BASE)) {
        Search::One(at) => Some(Codec::Lzx {
            tables: start.checked_add(at)?,
            call_marker: unique(find_patterns(code, CALL_FILTER))
                .and_then(|at| code.get(at.checked_add(CALL_MARKER_OFFSET)?).copied()),
        }),
        Search::Several => None,
        Search::None => find_pattern(code, APLIB_DEPACKER).map(|_| Codec::Aplib),
    }
}

fn restore(image: &PeImage<'_>, stub: &Stub, origin: &Origin<'_>) -> Step<Unpacked> {
    let model = image.model();
    let original_end = stub.start;
    let mut restored = image.bytes().to_vec();
    let mut report = PackerReport::new(NAME, None);
    let mut packed = origin
        .read_file()
        .and_then(|file| PackedFile::open(file.to_vec(), image.bytes(), stub));

    let resources = return_moved_resources(&mut restored, model, original_end);
    let unflagged = need(
        write_original_headers(&mut restored, model, stub),
        "the section table the stub keeps could not be written back",
    )?;
    report.restored(Part::Headers);
    report.record(Part::Resources, resources);

    match stub.block_layout {
        BlockLayout::Short => match flags_from_names(&mut restored, original_end) {
            Some(()) => report.inferred(Part::SectionFlags, "from the section names"),
            None => report.lost(Part::SectionFlags), // < 2.2
        },
        BlockLayout::Flagged if unflagged != 0 => {
            report.lost_with(Part::SectionFlags, "the stub keeps none for some sections");
        }
        BlockLayout::Flagged => {}
    }

    if stub.entry != 0 {
        report.restored(Part::EntryPoint);
    }

    let listed = packed
        .as_mut()
        .and_then(|packed| imports_from_original(&mut restored, model, stub.import_rva, packed));
    let imports = match listed {
        Some(listed) => {
            report.restored(Part::Imports);
            Some(listed)
        }
        None => {
            let scanned = restore_imports(&mut restored, model, stub, original_end, origin.base);
            match &scanned {
                Some(PackerImports::Listed(_)) => {
                    report.inferred(Part::Imports, "address table located by its shape");
                }
                Some(_) => report.inferred(Part::Imports, "from the filled IAT"),
                None => report.failed(Part::Imports),
            }
            scanned
        }
    };

    let relocations = match packed.as_mut() {
        Some(packed) => relocations_from_file(&mut restored, model, stub.relocations, packed),
        None => restore_relocations(&mut restored, model, stub.relocations),
    };
    report.record(Part::Relocations, relocations);

    let tls = restore_tls(&mut restored, model, origin.base, original_end, None);
    report.record(Part::Tls, tls);

    let writable = origin.writable_sections(model);
    recover_directories(
        &mut restored,
        model,
        origin.base,
        original_end,
        &writable,
        &mut report,
    );

    model.clear_directory(&mut restored, BOUND_IMPORT_DIRECTORY);
    model.clear_directory(&mut restored, RESERVED_DIRECTORY); // aspack puts a size in the reserved slot

    let fresh = packed.as_mut().and_then(|packed| {
        let original = packed.original_image(original_end)?;
        with_initial_data(
            image.bytes(),
            &restored,
            InitialData {
                bytes: &original,
                base: packed.base,
            },
            origin.base,
            original_end,
            &[],
        )
    });

    Unpacked::restored(restored, report, imports, fresh)
}

impl<'a> PackedFile<'a> {
    fn open(file: Vec<u8>, memory: &'a [u8], stub: &Stub) -> Option<Self> {
        let disk = parse_disk_image(&file).ok()?.into_model();
        let base = file_base(&file, &disk)?;
        let codec = stub.codec?;
        let tables = match codec {
            Codec::Lzx { tables, .. } => memory.get(tables..)?.get(..Tables::SIZE)?,
            Codec::Aplib => &[],
        };
        let mut packed = Self {
            file,
            base,
            disk,
            blocks: Vec::new(),
            codec,
            tables,
        };

        if let Codec::Lzx { tables, .. } = codec {
            (packed.raw(tables, Tables::SIZE)? == packed.tables).then_some(())?;
        }

        let table = stub.block_table?;
        let mut filtered = false;
        let mut terminated = false;

        for index in 0..MAX_BLOCKS {
            let entry_size = stub.block_layout.entry_size();
            let entry = table.checked_add(index.checked_mul(entry_size)?)?;
            let on_disk = packed.raw(entry, entry_size)?;
            let field = |offset: usize| read_u32(on_disk, offset).ok();
            let rva = field(0)? as usize;

            if rva == 0 {
                terminated = true;
                break;
            }

            let in_memory = |offset: usize| read_u32(memory, entry.checked_add(offset)?).ok();
            let unchanged = |offset: usize| field(offset) == in_memory(offset);
            let flagged = stub.block_layout == BlockLayout::Flagged;
            (unchanged(0) && (!flagged || unchanged(BLOCK_CHARACTERISTICS_OFFSET))).then_some(())?;

            let size = field(BLOCK_SIZE_OFFSET)?;
            let size = (!flagged || size != STORED_BLOCK).then_some(size as usize);
            size.is_none_or(|size| size <= memory.len()).then_some(())?;
            packed.blocks.push(Block {
                rva,
                size,
                filtered: size.is_some() && !filtered,
                decoded: None,
            });

            filtered |= size.is_some();
        }

        terminated.then_some(packed)
    }

    fn raw(&self, rva: usize, length: usize) -> Option<&[u8]> {
        let section = self
            .disk
            .sections
            .iter()
            .find(|section| section.range().contains(&rva))?;
        let offset = rva.checked_sub(section.virtual_address().as_usize())?;
        let available = (section.raw_size as usize).checked_sub(offset)?.min(length);
        let from = (section.raw_pointer as usize).checked_add(offset)?;
        self.file.get(from..from.checked_add(available)?)
    }

    fn original(&mut self, rva: usize, length: usize) -> Option<&[u8]> {
        let index = self.blocks.iter().position(|block| {
            block
                .size
                .is_some_and(|size| (block.rva..block.rva.saturating_add(size)).contains(&rva))
        });

        let Some(index) = index else {
            return self.raw(rva, length);
        };

        if self.blocks[index].decoded.is_none() {
            let decoded = self.decode(index)?;
            self.blocks[index].decoded = Some(decoded);
        }

        let block = &self.blocks[index];
        let offset = rva.checked_sub(block.rva)?;
        let decoded = block.decoded.as_deref()?;
        decoded.get(offset..offset.checked_add(length)?.min(decoded.len()))
    }

    fn decode(&self, index: usize) -> Option<Vec<u8>> {
        let block = self.blocks.get(index)?;
        let size = block.size?;

        match self.codec {
            Codec::Lzx { call_marker, .. } => {
                let source = self.raw(block.rva, size.checked_add(BLOCK_READ_SLACK)?)?;
                let mut decoded = decompress(source, size, &Tables::new(self.tables).ok()?).ok()?;
                if block.filtered {
                    let marker = call_marker?;
                    let end = decoded.len().saturating_sub(1); // stub stops one site short
                    call_filter::undo(
                        &mut decoded,
                        end,
                        CallFilter {
                            marks: Some([marker, marker]),
                            stored: Stored::Le24,
                            counted_from: 0,
                        },
                    );
                }

                Some(decoded)
            }
            Codec::Aplib => {
                let source = self.raw(block.rva, usize::MAX)?; // ends at marker
                let mut decoded =
                    aplib::decompress_exact(ByteTags::new(source), size, aplib::Variant::Original)
                        .ok()?;
                if block.filtered {
                    let end = decoded.len().saturating_sub(POSITION_FILTER_TAIL) + CALL_SIZE - 1;
                    call_filter::undo(
                        &mut decoded,
                        end,
                        CallFilter {
                            marks: None,
                            stored: Stored::Le32,
                            counted_from: 0,
                        },
                    );
                }

                Some(decoded)
            }
        }
    }

    fn original_image(&mut self, end: usize) -> Option<Vec<u8>> {
        let mut image = map_disk_image(&self.file, end)?;

        for index in 0..self.blocks.len() {
            let Some(size) = self.blocks[index].size else {
                continue;
            };

            let rva = self.blocks[index].rva;
            let decoded = self.original(rva, size)?.to_vec();
            if let Some(slot) = image.get_mut(rva..rva.saturating_add(decoded.len())) {
                slot.copy_from_slice(&decoded);
            }
        }

        Some(image)
    }
}

impl OriginalBytes for PackedFile<'_> {
    fn original_u32(&mut self, rva: usize) -> Option<u32> {
        Some(u32::from_le_bytes(self.original(rva, 4)?.try_into().ok()?))
    }

    fn original_string(&mut self, rva: usize) -> Option<String> {
        let text = self.original(rva, MAX_NAME_LENGTH)?;
        let mut terminated = text.to_vec();
        terminated.push(0);
        read_c_string(&terminated, 0).map(|(name, _)| name)
    }
}

fn relocations_from_file(
    restored: &mut [u8],
    model: &PeModel,
    relocations: StubRelocations,
    packed: &mut PackedFile<'_>,
) -> Restoration {
    let StubRelocations::At(start) = relocations else {
        return restore_relocations(restored, model, relocations);
    };

    let mut table = Vec::new();
    let mut at = start;
    while let (Some(page), Some(size)) = (
        packed.original_u32(at),
        packed.original_u32(at.saturating_add(RELOCATION_BLOCK_SIZE_OFFSET)),
    ) {
        let size = size as usize;

        if page == 0 || !(RELOCATION_BLOCK_HEADER..=MAX_RELOCATION_BLOCK).contains(&size) {
            break;
        }

        let in_memory = (
            read_u32(restored, at),
            read_u32(restored, at.saturating_add(RELOCATION_BLOCK_SIZE_OFFSET)),
        );

        let block = packed
            .original(at, size)
            .filter(|block| block.len() == size);
        let agrees = |memory_page: u32, memory_size: u32| {
            let same = memory_page == page && memory_size as usize == size;
            same || (memory_page, memory_size) == (0, 0) // the stub wipes the table once it applied it
        };
        match (in_memory, block) {
            ((Ok(memory_page), Ok(memory_size)), Some(block))
                if agrees(memory_page, memory_size) =>
            {
                table.extend_from_slice(block);
            }
            _ => return restore_relocations(restored, model, relocations),
        }

        at = at.saturating_add(size);
    }

    let written = restored
        .get_mut(start..start.saturating_add(table.len()))
        .filter(|_| !table.is_empty())
        .map(|slot| slot.copy_from_slice(&table))
        .and_then(|()| model.set_directory(restored, BASERELOC_DIRECTORY, start, table.len()));
    match written {
        Some(()) => Restoration::Restored,
        None => restore_relocations(restored, model, relocations),
    }
}

fn write_original_headers(restored: &mut [u8], model: &PeModel, stub: &Stub) -> Option<usize> {
    let sections = &model.sections;
    let mut unflagged = 0usize;

    for section in sections.get(..stub.index)? {
        let Some(flags) = original_flags(restored, stub, section) else {
            unflagged += 1;
            continue;
        };

        write_u32(
            restored,
            section
                .header_offset
                .checked_add(SECTION_CHARACTERISTICS_OFFSET)?,
            flags,
        )
        .ok()?;
    }

    let dropped = sections.get(stub.index)?.header_offset;
    let dropped_end = dropped.checked_add(
        sections
            .len()
            .checked_sub(stub.index)?
            .checked_mul(SECTION_HEADER_SIZE)?,
    )?;
    restored.get_mut(dropped..dropped_end)?.fill(0);
    write_u16(
        restored,
        model.nt_offset.checked_add(SECTION_COUNT_OFFSET)?,
        u16::try_from(stub.index).ok()?,
    )
    .ok()?;
    write_u32(
        restored,
        model.size_of_image_offset,
        u32::try_from(stub.start).ok()?,
    )
    .ok()?;
    write_u32(restored, model.entry_point_offset, stub.entry).ok()?;

    Some(unflagged)
}

fn original_flags(bytes: &[u8], stub: &Stub, section: &SectionModel) -> Option<u32> {
    let table = stub
        .block_table
        .filter(|_| stub.block_layout == BlockLayout::Flagged)?;
    let section = section.range();

    (0..MAX_BLOCKS)
        .map_while(|index| {
            let entry = table.checked_add(index.checked_mul(FLAGGED_BLOCK_ENTRY)?)?;
            let rva = read_u32(bytes, entry).ok().filter(|rva| *rva != 0)? as usize;
            Some((rva, entry))
        })
        .find(|(rva, _)| section.contains(rva))
        .and_then(|(_, entry)| {
            read_u32(bytes, entry.checked_add(BLOCK_CHARACTERISTICS_OFFSET)?).ok()
        })
}

fn restore_imports(
    restored: &mut [u8],
    model: &PeModel,
    stub: &Stub,
    original_end: usize,
    base: usize,
) -> Option<PackerImports> {
    let program = stub.first_section..original_end;
    let tables = thunk_tables(restored, stub.import_rva, base, program.start)?;
    let (first, span) = table_span(&tables)?;
    let lookups: Vec<_> = tables
        .iter()
        .map(|table| lookup_functions(restored, table, original_end))
        .collect();
    let named = lookups.iter().flatten().count();
    if named != 0 && named != lookups.len() {
        return None;
    }

    let listed = lookups.into_iter().collect::<Option<Vec<_>>>();
    let iat = match listed {
        Some(_) => find_iat(restored, &tables, base, &program)?,
        None => tables
            .iter()
            .all(|table| slots_filled(restored, table.start, table.count, base, original_end))
            .then_some(first)?, // borland: the lookup tables are the iat
    };

    model.clear_directory(restored, IMPORT_DIRECTORY);
    model.set_directory(restored, IAT_DIRECTORY, iat, span)?;

    let Some(listed) = listed else {
        let (rva, size) = (u32::try_from(iat).ok()?, u32::try_from(span).ok()?);
        return Some(PackerImports::FilledIat {
            rva,
            size,
            names: NameHints::new(),
        });
    };

    let modules = tables
        .iter()
        .zip(listed)
        .map(|(table, functions)| {
            let thunk = iat.checked_add(table.start.checked_sub(first)?)?;
            Some(ModuleImports {
                module: None,
                first_thunk: u32::try_from(thunk).ok()?,
                functions,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(PackerImports::Listed(modules))
}

fn lookup_functions(
    bytes: &[u8],
    table: &ThunkTable,
    original_end: usize,
) -> Option<Vec<ImportedFunction>> {
    (0..table.count)
        .map(|index| {
            let entry = read_u32(
                bytes,
                table.start.checked_add(index.checked_mul(THUNK_SIZE)?)?,
            )
            .ok()?;

            if entry & ORDINAL_FLAG != 0 {
                return Some(ImportedFunction::Ordinal(entry as u16));
            }

            let name = (entry as usize).checked_add(HINT_SIZE)?;

            if name >= original_end {
                return None;
            }

            Some(ImportedFunction::Name(read_c_string(bytes, name)?.0))
        })
        .collect()
}

fn thunk_tables(
    bytes: &[u8],
    import_rva: usize,
    base: usize,
    first_section: usize,
) -> Option<Vec<ThunkTable>> {
    let mut tables = Vec::new();
    for index in 0..MAX_IMPORT_DESCRIPTORS {
        let descriptor = import_rva.checked_add(index.checked_mul(IMPORT_DESCRIPTOR_SIZE)?)?;
        let lookup_end = read_u32(bytes, descriptor).ok()? as usize; // finished stub leaves the lookup end here

        if lookup_end == 0 {
            return (!tables.is_empty()).then_some(tables);
        }

        let end = lookup_end.checked_sub(base)?;
        let floor = end
            .saturating_sub(MAX_IMPORTS * THUNK_SIZE)
            .max(first_section);
        let mut start = end;
        while read_u32(bytes, start.checked_sub(THUNK_SIZE)?).ok()? != 0 {
            (start > floor).then_some(())?; // no zero before the table: its start is unknown
            start = start.checked_sub(THUNK_SIZE)?;
        }

        tables.push(ThunkTable {
            start,
            count: end.checked_sub(start)? / THUNK_SIZE,
        });
    }

    None
}

fn table_span(tables: &[ThunkTable]) -> Option<(usize, usize)> {
    iat_span(
        tables.iter().map(|table| (table.start, table.count)),
        THUNK_SIZE,
    )
}

fn slots_filled(bytes: &[u8], slots: usize, count: usize, base: usize, end: usize) -> bool {
    let program = base..base.saturating_add(end);

    (0..count).all(|index| {
        read_u32(
            bytes,
            slots.saturating_add(index.saturating_mul(THUNK_SIZE)),
        )
        .is_ok_and(|value| resolved_import(value as usize, &program))
    })
}

fn find_iat(
    bytes: &[u8],
    tables: &[ThunkTable],
    base: usize,
    program: &Range<usize>,
) -> Option<usize> {
    let (first, span) = table_span(tables)?;

    let matches = |candidate: usize| {
        tables.iter().all(|table| {
            let slots = candidate.saturating_add(table.start - first);
            let terminator = slots.saturating_add(table.count.saturating_mul(THUNK_SIZE));

            read_u32(bytes, terminator).is_ok_and(|value| value == 0)
                && slots_filled(bytes, slots, table.count, base, program.end)
        })
    };

    let candidates = (program.start..program.end.saturating_sub(span))
        .step_by(THUNK_SIZE)
        .filter(|candidate| *candidate != first && matches(*candidate))
        .collect::<Vec<_>>();
    if let [only] = candidates.as_slice() {
        return Some(*only);
    }

    most_referenced(bytes, &candidates, span, base, program)
}

fn most_referenced(
    bytes: &[u8],
    candidates: &[usize],
    span: usize,
    base: usize,
    program: &Range<usize>,
) -> Option<usize> {
    let mut owners = HashMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        for slot in (*candidate..candidate.saturating_add(span)).step_by(THUNK_SIZE) {
            owners.insert(base.saturating_add(slot), index);
        }
    }

    let mut references = vec![0usize; candidates.len()];
    let code = bytes.get(program.start..program.end.min(bytes.len()))?;

    for window in code.windows(THUNK_SIZE) {
        let address = u32::from_le_bytes([window[0], window[1], window[2], window[3]]) as usize;

        if let Some(index) = owners.get(&address) {
            references[*index] += 1;
        }
    }

    let best = references
        .iter()
        .copied()
        .max()
        .filter(|count| *count > 0)?;
    let mut winners = (0..references.len()).filter(|index| references[*index] == best);
    let winner = winners.next()?;
    winners.next().is_none().then(|| candidates[winner])
}

fn restore_relocations(
    restored: &mut [u8],
    model: &PeModel,
    relocations: StubRelocations,
) -> Restoration {
    let kept = match relocations {
        StubRelocations::At(start) => kept_relocations(restored, start),
        StubRelocations::Absent => Err(Restoration::Absent),
        StubRelocations::Unreadable => Err(Restoration::Failed),
    };

    let written = kept.and_then(|table| {
        model
            .set_directory(restored, BASERELOC_DIRECTORY, table.start, table.len())
            .ok_or(Restoration::Failed)
    });
    match written {
        Ok(()) => Restoration::Restored,
        Err(state) => {
            model.clear_directory(restored, BASERELOC_DIRECTORY);
            state
        }
    }
}

fn kept_relocations(bytes: &[u8], start: usize) -> Result<Range<usize>, Restoration> {
    let mut at = start;
    let mut wiped = false;

    while let Some((page, size)) = relocation_block(bytes, at) {
        if page == 0 || !(RELOCATION_BLOCK_HEADER..=MAX_RELOCATION_BLOCK).contains(&size) {
            break;
        }

        let end = at.saturating_add(size);
        let entries = bytes
            .get(at.saturating_add(RELOCATION_BLOCK_HEADER)..end)
            .ok_or(Restoration::Failed)?;
        wiped |= relocation_words(entries).any(|entry| entry == WIPED_RELOCATION);
        at = end;
    }

    if at == start || wiped {
        return Err(Restoration::Lost);
    }

    Ok(start..at)
}

fn return_moved_resources(
    restored: &mut [u8],
    model: &PeModel,
    original_end: usize,
) -> Restoration {
    let Some(directory) = model.directory(restored, RESOURCE_DIRECTORY) else {
        return Restoration::Absent;
    };

    let tree_start = directory.rva().as_usize();
    let Some(section) = model
        .sections
        .iter()
        .find(|section| section.contains_rva(directory.rva()))
    else {
        return Restoration::Failed;
    };

    return_moved_leaves(restored, tree_start, section.range(), original_end)
}

pub(super) struct Aspack;

impl Packer for Aspack {
    fn unpack(&self, image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
        unpack(image, origin)
    }

    fn original_code(&self, image: &PeImage<'_>, base: usize) -> Option<Vec<Range<usize>>> {
        original_code(image, base)
    }
}
