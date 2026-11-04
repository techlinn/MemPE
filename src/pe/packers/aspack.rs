use std::collections::HashMap;

use super::aplib;
use super::lzx::{Tables, decompress, unfilter_calls};
use super::tables::{
    FIRST_SECTION_RVA, RELOCATION_BLOCK_HEADER, RELOCATION_BLOCK_SIZE_OFFSET, Restoration,
    SECTION_CHARACTERISTICS_OFFSET, SECTION_COUNT_OFFSET, clear_directory, find_delay_directory,
    find_load_config, find_original_tls, fresh_image, iat_span, read_c_string, return_moved_leaves,
    set_directory, set_tls_directory,
};
use super::{
    ImportedFunction, ModuleImports, Origin, PackerFindings, PackerImports, PackerReport, Unpacked,
    find_pattern,
};
use crate::pe::image::{read_u32, write_u16, write_u32};
use crate::pe::parse::{parse_disk_image, parse_memory_image};
use crate::pe::{
    BASERELOC_DIRECTORY, BOUND_IMPORT_DIRECTORY, DELAY_IMPORT_DIRECTORY, IAT_DIRECTORY,
    IMPORT_DIRECTORY, LOAD_CONFIG_DIRECTORY, PeImage, PeKind, PeModel, RESOURCE_DIRECTORY, Rva,
    SECTION_HEADER_SIZE, SectionModel, TLS_DIRECTORY,
};

const NAME: &str = "ASPack";
const LEGACY_PROLOGUE: usize = 0x20;
const LEGACY_ENTRIES: [(&str, &str); 8] = [
    (
        "60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5",
        "1.0x",
    ),
    (
        "60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD",
        "1.08",
    ),
    (
        "60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ED",
        "1.08",
    ),
    ("60 EB 03 5D FF E5 E8 F8 FF FF FF 81 ED", "1.08"),
    ("60 E8 41 06 00 00 EB 41", "1.08.04"),
    ("60 E8 70 05 00 00 EB 4C", "2.000"),
    ("60 E8 72 05 00 00 EB 4C", "2.001"),
    ("60 E8 72 05 00 00 EB 33 87 DB 90 00", "2.1"),
];
const TAIL: &str = "C2 0C 00 68 ?? ?? ?? ?? C3"; // ret 0Ch, then push and ret to the entry point
const TAIL_PUSH_OFFSET: usize = 4;
const LEGACY_TAIL: &str = "8B 85 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 89 44 24 1C 61 FF E0"; // 1.x adds the loaded base to an entry rva
const LEGACY_TAIL_ENTRY_OFFSET: usize = 2;
const LEGACY_STUB_START: &str = "60 E8 00 00 00 00 5D 81 ED";
const IMPORT_LOAD: &str = "BE ?? ?? ?? ?? 8B 95 ?? ?? ?? ??"; // import rva, then the loaded base field
const IMPORT_RVA_OFFSET: usize = 1;
const IMPORT_BASE_OFFSET: usize = 7;
const IMPORT_FIELD_LOAD: &str = "8B B5 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 03 F2"; // older builds keep the rva in data
const IMPORT_FIELD_OFFSET: usize = 2;
const IMPORT_FIELD_BASE_OFFSET: usize = 8;
const LEGACY_IMPORT_LOAD: &str = "8B 95 ?? ?? ?? ?? 8B B5 ?? ?? ?? ?? 8B BD ?? ?? ?? ?? 03 F2";
const LEGACY_IMPORT_FIELD_OFFSET: usize = 8;
const LEGACY_IMPORT_BASE_OFFSET: usize = 2;
const RELOCATION_LOAD: &str = "C1 E8 10 ?? ?? 8B B5 ?? ?? ?? ??";
const RELOCATION_FIELD_OFFSET: usize = 7;
const BLOCK_LOOP: &str = "8D B5 ?? ?? ?? ?? 83 3E 00 0F 84"; // the decompression loop walks the block table
const BLOCK_LOOP_OFFSET: usize = 2;
const BLOCK_FLAGS_LOAD: &str = "0F B7 47 14 8D 7C 07 F0 8D B5 ?? ?? ?? ??"; // builds that restore section flags
const BLOCK_FLAGS_OFFSET: usize = 10;
const SHORT_BLOCK_ENTRY: usize = 8; // rva and unpacked size
const FLAGGED_BLOCK_ENTRY: usize = 12; // rva, unpacked size and the sections characteristics
const BLOCK_SIZE_OFFSET: usize = 4;
const BLOCK_CHARACTERISTICS_OFFSET: usize = 8;
const STORED_BLOCK: u32 = 0xFFFF_FEF2; // a block kept uncompressed in the file
const BLOCK_READ_SLACK: usize = 0x10E; // the stub hands the decoder this much more than the block
const MAX_BLOCKS: usize = 256;
const LENGTH_BASE: &str =
    "00 01 02 03 04 05 06 07 08 0A 0C 0E 10 14 18 1C 20 28 30 38 40 50 60 70 80 A0 C0 E0";
const CALL_FILTER: &str = "EB 00 80 3E ?? 75 F3"; // a zero jump selects the marker based call filter
const CALL_MARKER_OFFSET: usize = 4;
const APLIB_DEPACKER: &str = "B2 80 8A 06 46 88 07 47 02 D2 75 05 8A 16 46 12 D2";
const CALL: u8 = 0xE8;
const JUMP: u8 = 0xE9;
const CALL_SIZE: usize = 5;
const POSITION_FILTER_TAIL: usize = 6; // the 1.x filter stops this far from the end
const IMPORT_DESCRIPTOR_SIZE: usize = 20;
const IMPORT_NAME_OFFSET: usize = 12;
const IMPORT_IAT_OFFSET: usize = 16;
const MAX_IMPORT_DESCRIPTORS: usize = 4_096;
const MAX_THUNKS: usize = 65_536;
const THUNK_SIZE: usize = 4; // aspack only packs PE32 files
const ORDINAL_FLAG: u32 = 0x8000_0000;
const HINT_SIZE: usize = 2; // a name entry starts with its export hint
const MAX_NAME: usize = 4_096;
const MAX_RELOCATION_BLOCK: usize = 0x10000;
const WIPED_RELOCATION: u16 = 0xFFFF; // the stub overwrites each entry after applying it
const LOAD_CONFIG_DIRECTORY_SIZE: usize = 0x40; // msvc PE32 value, the loader reads the struct's own size
const RESERVED_DIRECTORY: usize = 15;

struct Stub {
    index: usize,
    block_entry: usize,
    start: usize,
    entry: Option<u32>,
    import_rva: usize,
    relocation_rva: Option<usize>,
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

struct RawSection {
    rva: usize,
    span: usize,
    offset: usize,
    size: usize,
}

struct PackedFile<'a> {
    file: Vec<u8>,
    base: usize,
    sections: Vec<RawSection>,
    blocks: Vec<Block>,
    codec: Codec,
    tables: &'a [u8],
}

pub(super) fn unpack(image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
    let model = image.model();

    if !matches!(model.kind(), PeKind::Pe32) {
        return None;
    }

    let Some(stub) = find_stub(image.bytes(), model, origin.base) else {
        let reason = "image (mempe can't restore this ASPack release yet)";
        return legacy_release(image.bytes(), model)
            .map(|release| Unpacked::detected_only(NAME, Some(release.to_owned()), reason));
    };

    if stub.entry.is_none() {
        let reason = "image (the stub had not finished unpacking)";
        return Some(Unpacked::detected_only(NAME, None, reason));
    }

    let reason = "image (its tables could not be read)";
    restore(image, &stub, origin).or_else(|| Some(Unpacked::detected_only(NAME, None, reason)))
}

fn legacy_release(bytes: &[u8], model: &PeModel) -> Option<&'static str> {
    let entry = read_u32(bytes, model.entry_point_offset).ok()? as usize;
    let first_section = model.sections().first()?;
    (!first_section.contains_rva(Rva(entry as u32)) && entry != 0).then_some(())?;

    let code = bytes.get(entry..entry.saturating_add(LEGACY_PROLOGUE).min(bytes.len()))?;
    LEGACY_ENTRIES
        .iter()
        .find(|(pattern, _)| find_pattern(code, pattern) == Some(0))
        .map(|(_, release)| *release)
}

fn find_stub(bytes: &[u8], model: &PeModel, base: usize) -> Option<Stub> {
    let entry = Rva(read_u32(bytes, model.entry_point_offset).ok()?);
    model
        .sections()
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(_, section)| {
            section.is_executable()
                || section.contains_rva(entry)
                || starts_legacy_stub(bytes, section)
        }) // 2.12 and older mark nothing executable
        .find_map(|(index, section)| stub_in_section(bytes, index, section, base))
}

fn starts_legacy_stub(bytes: &[u8], section: &SectionModel) -> bool {
    let start = section.virtual_address().as_usize();
    bytes
        .get(start..start.saturating_add(LEGACY_PROLOGUE).min(bytes.len()))
        .is_some_and(|code| find_pattern(code, LEGACY_STUB_START) == Some(0)) // the stub puts the planted jump back once it runs
}

fn stub_in_section(
    bytes: &[u8],
    index: usize,
    section: &SectionModel,
    base: usize,
) -> Option<Stub> {
    let start = section.virtual_address().as_usize();
    let end = start
        .saturating_add(section.span() as usize)
        .min(bytes.len());
    let code = bytes.get(start..end)?;
    let tail = find_pattern(code, TAIL).and_then(|at| start.checked_add(at));
    (tail.is_some() || find_pattern(code, LEGACY_TAIL).is_some()).then_some(())?;

    let read = |at: usize| read_u32(bytes, at).ok();
    let load = |pattern: &str, field: usize, base: usize| -> Option<(u32, u32)> {
        let at = start.checked_add(find_pattern(code, pattern)?)?;
        Some((read(at.checked_add(field)?)?, read(at.checked_add(base)?)?))
    };

    let (import_rva, import_field, base_field) =
        match load(IMPORT_LOAD, IMPORT_RVA_OFFSET, IMPORT_BASE_OFFSET) {
            Some((rva, base)) => (Some(rva), None, base),
            None => {
                let (field, base) = load(
                    IMPORT_FIELD_LOAD,
                    IMPORT_FIELD_OFFSET,
                    IMPORT_FIELD_BASE_OFFSET,
                )
                .or_else(|| {
                    load(
                        LEGACY_IMPORT_LOAD,
                        LEGACY_IMPORT_FIELD_OFFSET,
                        LEGACY_IMPORT_BASE_OFFSET,
                    )
                })?;
                (None, Some(field), base)
            }
        };

    let base32 = u32::try_from(base).ok()?; // aspack only packs PE32 images
    let in_original = |rva: usize| (FIRST_SECTION_RVA..start).contains(&rva);
    let displacement = |pattern: &str, offset: usize| -> Option<u32> {
        read(
            start
                .checked_add(find_pattern(code, pattern)?)?
                .checked_add(offset)?,
        )
    };

    let block_field = displacement(BLOCK_LOOP, BLOCK_LOOP_OFFSET);
    let consistent = |ebp: u32| {
        let at = |field: u32| read(ebp.wrapping_add(field) as usize);
        let points_inside = |field: Option<u32>| {
            field.is_none_or(|field| at(field).is_some_and(|rva| in_original(rva as usize)))
        };

        at(base_field) == Some(base32) && points_inside(import_field) && points_inside(block_field)
    };

    let ebp = stub_bases(code, start, base32, base_field).find(|ebp| consistent(*ebp));
    let field = |pattern: &str, offset: usize| -> Option<usize> {
        Some(ebp?.wrapping_add(displacement(pattern, offset)?) as usize)
    };

    let import_rva = match (import_rva, import_field) {
        (Some(rva), _) => rva as usize,
        (None, field) => read(ebp?.wrapping_add(field?) as usize)? as usize,
    };
    in_original(import_rva).then_some(())?;

    let relocation_rva = field(RELOCATION_LOAD, RELOCATION_FIELD_OFFSET)
        .and_then(read)
        .map(|rva| rva as usize)
        .filter(|rva| in_original(*rva));

    let entry = match tail {
        Some(tail) => {
            let pushed = read(tail.checked_add(TAIL_PUSH_OFFSET)?)? as usize;
            pushed
                .checked_sub(base)
                .filter(|rva| ebp.is_some() && pushed != 0 && (*rva == 0 || in_original(*rva))) // a dll without an entry point pushes its base
        }
        None => field(LEGACY_TAIL, LEGACY_TAIL_ENTRY_OFFSET)
            .and_then(read)
            .map(|rva| rva as usize)
            .filter(|rva| *rva == 0 || in_original(*rva)),
    }
    .and_then(|rva| u32::try_from(rva).ok());

    let codec = match find_pattern(code, LENGTH_BASE).and_then(|at| start.checked_add(at)) {
        Some(tables) => Some(Codec::Lzx {
            tables,
            call_marker: find_pattern(code, CALL_FILTER)
                .and_then(|at| code.get(at.checked_add(CALL_MARKER_OFFSET)?).copied()),
        }),
        None => find_pattern(code, APLIB_DEPACKER).map(|_| Codec::Aplib),
    };
    let flagged = field(BLOCK_FLAGS_LOAD, BLOCK_FLAGS_OFFSET);

    Some(Stub {
        index,
        block_entry: match flagged {
            Some(_) => FLAGGED_BLOCK_ENTRY,
            None => SHORT_BLOCK_ENTRY,
        },
        start,
        entry,
        import_rva,
        relocation_rva,
        block_table: field(BLOCK_LOOP, BLOCK_LOOP_OFFSET).or(flagged),
        codec,
    })
}

fn stub_bases(
    code: &[u8],
    start: usize,
    base: u32,
    base_field: u32,
) -> impl Iterator<Item = u32> + '_ {
    let wanted = base.to_le_bytes();
    code.windows(wanted.len())
        .enumerate()
        .filter(move |(_, window)| *window == wanted)
        .filter_map(move |(at, _)| u32::try_from(start + at).ok())
        .map(move |at| at.wrapping_sub(base_field))
}

fn restore(image: &PeImage<'_>, stub: &Stub, origin: &Origin<'_>) -> Option<Unpacked> {
    let model = image.model();
    let original_end = stub.start;
    let mut restored = image.bytes().to_vec();
    let mut report = PackerReport::new(NAME, None);
    let mut packed = origin
        .read_file()
        .and_then(|file| PackedFile::open(file, image.bytes(), stub));

    report.restored.push("headers");
    let resources = return_moved_resources(&mut restored, model, original_end);
    report.record("resources", resources);
    write_original_headers(&mut restored, model, stub)?;

    if stub.block_entry == SHORT_BLOCK_ENTRY {
        report.lost.push("section flags"); // builds before 2.2 never stored them
    }

    if stub.entry != Some(0) {
        report.restored.push("entry point");
    }

    let imports = packed
        .as_mut()
        .and_then(|packed| imports_from_file(&mut restored, model, stub, packed))
        .or_else(|| restore_imports(&mut restored, model, stub, original_end, origin.base));
    match &imports {
        Some(PackerImports::Listed(_)) => report.restored.push("imports"),
        Some(_) => report.restored.push("imports (from the filled IAT)"),
        None => report.unrestored.push("imports"),
    }

    let relocations = match packed.as_mut() {
        Some(packed) => relocations_from_file(&mut restored, model, stub.relocation_rva, packed),
        None => restore_relocations(&mut restored, model, stub.relocation_rva),
    };
    report.record("relocations", relocations);

    let tls = restore_tls(&mut restored, model, original_end);
    report.record("TLS", tls);

    if let Some(rva) = find_load_config(&restored, PeKind::Pe32, origin.base, original_end) {
        set_directory(
            &mut restored,
            model,
            LOAD_CONFIG_DIRECTORY,
            rva,
            LOAD_CONFIG_DIRECTORY_SIZE,
        )?;
        report.restored.push("load config");
    }

    if let Some((rva, size)) = find_delay_directory(&restored, original_end) {
        set_directory(&mut restored, model, DELAY_IMPORT_DIRECTORY, rva, size)?;
        report.restored.push("delay imports");
    }

    clear_directory(&mut restored, model, BOUND_IMPORT_DIRECTORY);
    clear_directory(&mut restored, model, RESERVED_DIRECTORY);
    parse_memory_image(&restored).ok()?;

    let fresh = packed.as_mut().and_then(|packed| {
        let original = packed.original_image(original_end)?;
        fresh_image(
            image.bytes(),
            &restored,
            &original,
            packed.base,
            origin.base,
            original_end,
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

impl<'a> PackedFile<'a> {
    fn open(file: Vec<u8>, memory: &'a [u8], stub: &Stub) -> Option<Self> {
        let disk = parse_disk_image(&file).ok()?;
        let base = read_u32(&file, disk.model().image_base_offset).ok()? as usize;
        let sections = disk
            .model()
            .sections()
            .iter()
            .map(|section| RawSection {
                rva: section.virtual_address().as_usize(),
                span: section.span() as usize,
                offset: section.raw_pointer as usize,
                size: section.raw_size as usize,
            })
            .collect::<Vec<_>>();
        let codec = stub.codec?;
        let tables = match codec {
            Codec::Lzx { tables, .. } => memory.get(tables..)?.get(..Tables::SIZE)?,
            Codec::Aplib => &[],
        };
        let mut packed = Self {
            file,
            base,
            sections,
            blocks: Vec::new(),
            codec,
            tables,
        };

        if let Codec::Lzx { tables, .. } = codec {
            (packed.raw(tables, Tables::SIZE)? == packed.tables).then_some(())?;
        }

        let table = stub.block_table?;
        let mut filtered = false;

        for index in 0..MAX_BLOCKS {
            let entry = table.checked_add(index.checked_mul(stub.block_entry)?)?;
            let on_disk = packed.raw(entry, stub.block_entry)?;
            let field = |offset: usize| read_u32(on_disk, offset).ok();
            let rva = field(0)? as usize;

            if rva == 0 {
                break;
            }

            let unchanged = |offset: usize| field(offset) == read_u32(memory, entry + offset).ok();
            let flagged = stub.block_entry == FLAGGED_BLOCK_ENTRY;
            (unchanged(0) && (!flagged || unchanged(BLOCK_CHARACTERISTICS_OFFSET))).then_some(())?;

            let size = field(BLOCK_SIZE_OFFSET)?;
            let size = (!flagged || size != STORED_BLOCK).then_some(size as usize);
            packed.blocks.push(Block {
                rva,
                size,
                filtered: size.is_some() && !filtered,
                decoded: None,
            });

            filtered |= size.is_some();
        }

        Some(packed)
    }

    fn raw(&self, rva: usize, length: usize) -> Option<&[u8]> {
        let section = self
            .sections
            .iter()
            .find(|section| (section.rva..section.rva + section.span).contains(&rva))?;
        let offset = rva.checked_sub(section.rva)?;
        let available = section.size.checked_sub(offset)?.min(length);
        let from = section.offset.checked_add(offset)?;
        self.file.get(from..from.checked_add(available)?)
    }

    fn original(&mut self, rva: usize, length: usize) -> Option<&[u8]> {
        let index = self.blocks.iter().position(|block| {
            block
                .size
                .is_some_and(|size| (block.rva..block.rva + size).contains(&rva))
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
                let mut decoded = decompress(source, size, &Tables::new(self.tables)?)?;
                if block.filtered {
                    unfilter_calls(&mut decoded, call_marker?);
                }

                Some(decoded)
            }
            Codec::Aplib => {
                let source = self.raw(block.rva, usize::MAX)?; // the stream ends at its own marker
                let mut decoded = aplib::decompress(source, size)?;
                (decoded.len() == size).then_some(())?;
                if block.filtered {
                    unfilter_positions(&mut decoded);
                }

                Some(decoded)
            }
        }
    }

    fn original_image(&mut self, end: usize) -> Option<Vec<u8>> {
        let mut image = vec![0u8; end];

        for section in &self.sections {
            let length = section.size.min(section.span);
            let raw = self
                .file
                .get(section.offset..section.offset.checked_add(length)?)?;
            if let Some(slot) = image.get_mut(section.rva..section.rva.saturating_add(raw.len())) {
                slot.copy_from_slice(raw);
            }
        }

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

    fn read_u32(&mut self, rva: usize) -> Option<u32> {
        Some(u32::from_le_bytes(self.original(rva, 4)?.try_into().ok()?))
    }

    fn read_string(&mut self, rva: usize) -> Option<String> {
        let text = self.original(rva, MAX_NAME)?;
        let mut terminated = text.to_vec();
        terminated.push(0);
        read_c_string(&terminated, 0).map(|(name, _)| name)
    }
}

fn unfilter_positions(bytes: &mut [u8]) {
    let mut remaining = bytes.len().saturating_sub(POSITION_FILTER_TAIL);
    let mut at = 0;

    while remaining > 0 {
        let Some(&opcode) = bytes.get(at) else {
            return;
        };

        if !matches!(opcode, CALL | JUMP) {
            at += 1;
            remaining -= 1;
            continue;
        }

        let operand = at + 1;
        let Ok(target) = read_u32(bytes, operand) else {
            return;
        };
        let relative = target.wrapping_sub(at as u32); // the packer stored call targets as positions
        if write_u32(bytes, operand, relative).is_err() {
            return;
        }

        at += CALL_SIZE;
        remaining = remaining.saturating_sub(CALL_SIZE);
    }
}

fn imports_from_file(
    restored: &mut [u8],
    model: &PeModel,
    stub: &Stub,
    packed: &mut PackedFile<'_>,
) -> Option<PackerImports> {
    let mut modules = Vec::new();
    for index in 0..MAX_IMPORT_DESCRIPTORS {
        let descriptor = stub
            .import_rva
            .checked_add(index.checked_mul(IMPORT_DESCRIPTOR_SIZE)?)?;
        let lookup = packed.read_u32(descriptor)? as usize;
        let name = packed.read_u32(descriptor.checked_add(IMPORT_NAME_OFFSET)?)? as usize;
        let iat = packed.read_u32(descriptor.checked_add(IMPORT_IAT_OFFSET)?)? as usize;

        if name == 0 && iat == 0 {
            break;
        }

        let module = packed.read_string(name)?;
        let source = match lookup {
            0 => iat, // borland linkers leave the names in the iat itself
            _ => lookup,
        };

        let mut functions = Vec::new();
        for slot in 0..MAX_THUNKS {
            let entry = packed.read_u32(source.checked_add(slot.checked_mul(THUNK_SIZE)?)?)?;

            if entry == 0 {
                break;
            }

            functions.push(match entry & ORDINAL_FLAG {
                0 => ImportedFunction::Name(
                    packed.read_string((entry as usize).checked_add(HINT_SIZE)?)?,
                ),
                _ => ImportedFunction::Ordinal(entry as u16),
            });
        }

        let filled = |slot: usize| {
            read_u32(restored, iat.saturating_add(slot * THUNK_SIZE)).is_ok_and(|value| value != 0)
        };
        let matches_memory = (0..functions.len()).all(filled) && !filled(functions.len());
        matches_memory.then_some(())?;
        modules.push(ModuleImports {
            module,
            first_thunk: u32::try_from(iat).ok()?,
            functions,
        });
    }

    let tables = modules
        .iter()
        .map(|module| (module.first_thunk as usize, module.functions.len()));
    let (first, span) = iat_span(tables, THUNK_SIZE)?;
    clear_directory(restored, model, IMPORT_DIRECTORY);
    set_directory(restored, model, IAT_DIRECTORY, first, span)?;

    Some(PackerImports::Listed(modules))
}

fn relocations_from_file(
    restored: &mut [u8],
    model: &PeModel,
    relocation_rva: Option<usize>,
    packed: &mut PackedFile<'_>,
) -> Restoration {
    let Some(start) = relocation_rva else {
        clear_directory(restored, model, BASERELOC_DIRECTORY);
        return Restoration::Absent;
    };

    let mut table = Vec::new();
    let mut at = start;
    while let (Some(page), Some(size)) = (
        packed.read_u32(at),
        packed.read_u32(at.saturating_add(RELOCATION_BLOCK_SIZE_OFFSET)),
    ) {
        let size = size as usize;

        if page == 0 || !(RELOCATION_BLOCK_HEADER..=MAX_RELOCATION_BLOCK).contains(&size) {
            break;
        }

        let in_memory = (
            read_u32(restored, at),
            read_u32(restored, at + RELOCATION_BLOCK_SIZE_OFFSET),
        );

        let block = packed
            .original(at, size)
            .filter(|block| block.len() == size);
        match (in_memory, block) {
            ((Ok(memory_page), Ok(memory_size)), Some(block))
                if memory_page == page && memory_size as usize == size =>
            {
                table.extend_from_slice(block);
            }
            _ => return restore_relocations(restored, model, relocation_rva),
        }

        at = at.saturating_add(size);
    }

    let written = restored
        .get_mut(start..start.saturating_add(table.len()))
        .filter(|_| !table.is_empty())
        .map(|slot| slot.copy_from_slice(&table))
        .and_then(|()| set_directory(restored, model, BASERELOC_DIRECTORY, start, table.len()));
    match written {
        Some(()) => Restoration::Restored,
        None => restore_relocations(restored, model, relocation_rva),
    }
}

fn write_original_headers(restored: &mut [u8], model: &PeModel, stub: &Stub) -> Option<()> {
    let sections = model.sections();

    for section in sections.get(..stub.index)? {
        if let Some(flags) = original_flags(restored, stub, section) {
            write_u32(
                restored,
                section
                    .header_offset
                    .checked_add(SECTION_CHARACTERISTICS_OFFSET)?,
                flags,
            )
            .ok()?;
        }
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
    write_u32(restored, model.entry_point_offset, stub.entry?).ok()
}

fn original_flags(bytes: &[u8], stub: &Stub, section: &SectionModel) -> Option<u32> {
    let table = stub
        .block_table
        .filter(|_| stub.block_entry == FLAGGED_BLOCK_ENTRY)?;
    let start = section.virtual_address().as_usize();
    let end = start.saturating_add(section.span() as usize);

    (0..MAX_BLOCKS)
        .map_while(|index| {
            let entry = table.checked_add(index.checked_mul(FLAGGED_BLOCK_ENTRY)?)?;
            let rva = read_u32(bytes, entry).ok().filter(|rva| *rva != 0)? as usize;
            Some((rva, entry))
        })
        .find(|(rva, _)| (start..end).contains(rva))
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
    let tables = thunk_tables(restored, stub.import_rva, base)?;
    let (first, span) = table_span(&tables)?;
    let listed = tables
        .iter()
        .map(|table| lookup_functions(restored, table, original_end))
        .collect::<Option<Vec<_>>>();
    let iat = match listed {
        Some(_) => find_iat(restored, &tables, base, original_end)?,
        None => first, // a table without names was the iat itself
    };

    clear_directory(restored, model, IMPORT_DIRECTORY);
    set_directory(restored, model, IAT_DIRECTORY, iat, span)?;

    let Some(listed) = listed else {
        let (rva, size) = (u32::try_from(iat).ok()?, u32::try_from(span).ok()?);
        return Some(PackerImports::FilledIat { rva, size });
    };

    let modules = tables
        .iter()
        .zip(listed)
        .map(|(table, functions)| {
            let thunk = iat.checked_add(table.start.checked_sub(first)?)?;
            Some(ModuleImports {
                module: String::new(),
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

fn thunk_tables(bytes: &[u8], import_rva: usize, base: usize) -> Option<Vec<ThunkTable>> {
    let mut tables = Vec::new();
    for index in 0..MAX_IMPORT_DESCRIPTORS {
        let descriptor = import_rva.checked_add(index.checked_mul(IMPORT_DESCRIPTOR_SIZE)?)?;
        let terminator = read_u32(bytes, descriptor).ok()? as usize;

        if terminator == 0 {
            return (!tables.is_empty()).then_some(tables);
        }

        let end = terminator.checked_sub(base)?;
        let mut start = end;
        while start > FIRST_SECTION_RVA
            && read_u32(bytes, start.checked_sub(THUNK_SIZE)?).ok()? != 0
        {
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

fn find_iat(
    bytes: &[u8],
    tables: &[ThunkTable],
    base: usize,
    original_end: usize,
) -> Option<usize> {
    let (first, span) = table_span(tables)?;
    let filled = |value: u32| {
        value != 0 && !(base..base.saturating_add(original_end)).contains(&(value as usize))
    };

    let matches = |candidate: usize| {
        tables.iter().all(|table| {
            let slots = candidate.saturating_add(table.start - first);
            let slot =
                |index: usize| read_u32(bytes, slots.saturating_add(index * THUNK_SIZE)).ok();
            slot(table.count) == Some(0)
                && (0..table.count).all(|index| slot(index).is_some_and(filled))
        })
    };

    let candidates = (FIRST_SECTION_RVA..original_end.saturating_sub(span))
        .step_by(THUNK_SIZE)
        .filter(|candidate| *candidate != first && matches(*candidate))
        .collect::<Vec<_>>();
    if let [only] = candidates.as_slice() {
        return Some(*only);
    }

    most_referenced(bytes, &candidates, span, base, original_end)
}

fn most_referenced(
    bytes: &[u8],
    candidates: &[usize],
    span: usize,
    base: usize,
    original_end: usize,
) -> Option<usize> {
    let mut owners = HashMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        for slot in (*candidate..candidate.saturating_add(span)).step_by(THUNK_SIZE) {
            owners.insert(base.saturating_add(slot), index); // x86 code reaches iat slots by address
        }
    }

    let mut references = vec![0usize; candidates.len()];
    let code = bytes.get(FIRST_SECTION_RVA..original_end.min(bytes.len()))?;

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
    relocation_rva: Option<usize>,
) -> Restoration {
    let Some(start) = relocation_rva else {
        clear_directory(restored, model, BASERELOC_DIRECTORY);
        return Restoration::Absent;
    };

    let mut at = start;
    let mut wiped = true;
    while let (Ok(page), Ok(size)) = (
        read_u32(restored, at),
        read_u32(restored, at.saturating_add(RELOCATION_BLOCK_SIZE_OFFSET)),
    ) {
        let size = size as usize;

        if page == 0 || !(RELOCATION_BLOCK_HEADER..=MAX_RELOCATION_BLOCK).contains(&size) {
            break;
        }

        let entries = restored
            .get(at.saturating_add(RELOCATION_BLOCK_HEADER)..at.saturating_add(size))
            .unwrap_or_default();
        wiped &= entries
            .as_chunks::<2>()
            .0
            .iter()
            .all(|entry| u16::from_le_bytes(*entry) == WIPED_RELOCATION);
        at = at.saturating_add(size);
    }

    if at == start || wiped {
        clear_directory(restored, model, BASERELOC_DIRECTORY);
        return Restoration::Lost;
    }

    match set_directory(restored, model, BASERELOC_DIRECTORY, start, at - start) {
        Some(()) => Restoration::Restored,
        None => Restoration::Failed,
    }
}

fn restore_tls(restored: &mut [u8], model: &PeModel, original_end: usize) -> Restoration {
    let Ok(Some(copy)) = model.directory(restored, TLS_DIRECTORY) else {
        return Restoration::Absent;
    };

    let original = find_original_tls(restored, copy.rva().as_usize(), PeKind::Pe32, original_end);

    match original.and_then(|rva| set_tls_directory(restored, model, rva)) {
        Some(()) => Restoration::Restored,
        None => {
            clear_directory(restored, model, TLS_DIRECTORY);
            Restoration::Failed
        }
    }
}

fn return_moved_resources(
    restored: &mut [u8],
    model: &PeModel,
    original_end: usize,
) -> Restoration {
    let Ok(Some(directory)) = model.directory(restored, RESOURCE_DIRECTORY) else {
        return Restoration::Absent;
    };

    let tree_start = directory.rva().as_usize();
    let Some(section) = model
        .sections()
        .iter()
        .find(|section| section.contains_rva(directory.rva()))
    else {
        return Restoration::Failed;
    };

    let region_start = section.virtual_address().as_usize();
    let region = region_start..region_start.saturating_add(section.span() as usize);
    return_moved_leaves(restored, tree_start, region, original_end)
}
