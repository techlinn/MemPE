use std::ops::Range;

use super::Packer;
use crate::pe::bytes::{read_u16, read_u32, write_u32};
use crate::pe::parse::{MACHINE_AMD64, MACHINE_I386, parse_disk_image, parse_memory_image};
use crate::pe::{
    BASERELOC_DIRECTORY, BOUND_IMPORT_DIRECTORY, DEBUG_DIRECTORY, DEBUG_ENTRY_SIZE,
    DEBUG_TYPE_OFFSET, EXPORT_DIRECTORY, FILE_CHARACTERISTICS_OFFSET, FILE_HEADER_SIZE,
    GUARD_FLAGS_PE32, GUARD_FLAGS_PE32_PLUS, IMAGE_SCN_MEM_WRITE, IMPORT_DIRECTORY,
    LOAD_CONFIG_DIRECTORY, MACHINE_OFFSET, MAX_IMPORT_DESCRIPTORS, MAX_IMPORTS, MAX_RELOCATIONS,
    OPTIONAL_SIZE_OFFSET, PE_SIGNATURE, PeImage, PeKind, PeModel, RELOCATION_HIGH, RELOCATION_LOW,
    RELOCS_STRIPPED, RESOURCE_DIRECTORY, Rva, SECTION_ALIGNMENT_OFFSET, SECTION_COUNT_OFFSET,
    SECTION_HEADER_SIZE, SECTION_RVA_OFFSET, SectionModel, TIMESTAMP_OFFSET,
};
use crate::unpack::codecs::lzma;
use crate::unpack::codecs::nrv::{self, Variant};
use crate::unpack::tables::{
    DEBUG_TYPE_CODEVIEW, Restoration, codeview_entry, export_forwarders, exports_intact,
    find_codeview_record, iat_filled, is_free, linker_export_layout, moved_export_directory, place,
    read_c_string, relocate, relocation_blocks, relocations_intact, resource_leaf,
    resources_intact, restored_or_cleared, unique, walk_resources,
};
use crate::unpack::{
    FreshCopy, HeaderSource, ImportedFunction, InitialData, ModuleImports, Origin, PackerId,
    PackerImports, PackerReport, Part, Refusal, Step, Unpacked, file_base, find_pattern, hex, need,
    with_initial_data,
};

const NAME: PackerId = PackerId::Upx;
const MAX_STORED_CANDIDATES: usize = 32;
const PACK_HEADER_MAGIC: &[u8; 4] = b"UPX!";
const PACK_HEADER_WINDOW: usize = 0x1000;
const UNCOMPRESSED_LENGTH_OFFSET: usize = 16; // u_len inside the pack header
const VERSION_LENGTH: usize = 4; // "5.30" before a nul and the magic
const FILE_HEADER_END: usize = PE_SIGNATURE.len() + FILE_HEADER_SIZE;
const EXTRA_INFO_SCAN: usize = 0x1000;
const EXTRA_INFO_OFFSET_SIZE: usize = 4; // trailing u32, offset of extra info
const IMPORT_FIELDS_SIZE: usize = 8; // import list offset and dll string rva
const RELOCATION_FIELDS_SIZE: usize = 5; // stream offset and 16-bit list flags
const RELOCATION_FLAGS_OFFSET: usize = 4;
const ICON_COUNT_SIZE: usize = 2;
const EXACT_TRAILER: usize = 8; // flags and gap size before the final offset
const EXACT_GAP_OFFSET: usize = 4;
const MAX_EXACT_GAP: usize = 1 << 20;
const EXACT_RELOCATIONS: u32 = 1;
const MODULE_IAT_OFFSET: usize = 4; // after the u32 name offset
const MODULE_HEADER_SIZE: usize = 8;
const IMPORT_BY_NAME: u8 = 0x01;
const IMPORT_BY_ORDINAL: u8 = 0xFF;
const IMPORT_KERNEL32_THUNK: u8 = 0xFE;
const ORDINAL_RECORD_SIZE: usize = 3; // tag and u16 ordinal
const THUNK_RECORD_SIZE: usize = 5; // tag and u32 thunk
const RELOCATION_STREAM_ORIGIN: isize = -4; // first delta counts from here
const LONG_DELTA: u8 = 0xF0; // 3 or 7 byte delta
const LONG_DELTA_HIGH_BITS: u8 = 0x0F;
const HIGH_LIST: u8 = 2; // x86 16-bit lists after the stream
const LOW_LIST: u8 = 4;
const EMPTY_RELOCATION_BLOCK: [u8; 8] = [0, 0, 0, 0, 8, 0, 0, 0];
const ORIGINAL_RVA_PREFIX: usize = 4; // kept leaf follows its original rva
const PACK_HEADER_SIZE: usize = 32;
const FORMAT_OFFSET: usize = 5;
const METHOD_OFFSET: usize = 6;
const PE_FORMATS: [u8; 2] = [9, 36]; // win32/pe and win64/pe
const CHECKSUM_START: usize = 4; // the checksum skips the magic
const CHECKSUM_MODULO: u32 = 251;
const UNCOMPRESSED_ADLER_OFFSET: usize = 8;
const COMPRESSED_ADLER_OFFSET: usize = 12;
const COMPRESSED_LENGTH_OFFSET: usize = 20;
const FILTER_OFFSET: usize = 28;
const METHOD_NRV2B: u8 = 2;
const METHOD_NRV2D: u8 = 5;
const METHOD_NRV2E: u8 = 8;
const METHOD_LZMA: u8 = 14;
const METHODS: [u8; 4] = [METHOD_NRV2B, METHOD_NRV2D, METHOD_NRV2E, METHOD_LZMA];
const LZMA_HEADER: usize = 2; // upx's two property bytes
const LZMA_LITERAL_CONTEXT_MASK: u8 = 0x0F;
const LZMA_LITERAL_POSITION_SHIFT: u8 = 4;
const LZMA_POSITION_MASK: u8 = 0x07;
const ADLER_MODULO: u32 = 65_521;
const GUARD_FUNCTION_COUNT_PE32: usize = 0x54; // inside the load config
const GUARD_FUNCTION_COUNT_PE32_PLUS: usize = 0x88;
const GUARD_CF_INSTRUMENTED: u32 = 0x100;

struct StubPatterns {
    stack_clear: &'static str,
    stack_clear_core: &'static str,
    import_loop: &'static str,
    import_list_operand: usize,
    import_names_operand: usize,
}

const X64_STUB: StubPatterns = StubPatterns {
    stack_clear: hex("48 8D 44 24 80 6A 00 48 39 C4 75 F9 48 83 EC 80"),
    stack_clear_core: hex("6A 00 48 39 C4 75 F9"),
    import_loop: hex(
        "48 83 EC 28 48 8D BE ?? ?? ?? ?? 8B 07 09 C0 74 ?? 8B 5F 04 48 8D 8C 30 ?? ?? ?? ??",
    ),
    import_list_operand: 7,
    import_names_operand: 24,
};

const X86_STUB: StubPatterns = StubPatterns {
    stack_clear: hex("8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80"),
    stack_clear_core: hex("6A 00 39 C4 75 FA"),
    import_loop: hex("8D BE ?? ?? ?? ?? 8B 07 09 C0 74 ?? 8B 5F 04 8D 84 30 ?? ?? ?? ??"),
    import_list_operand: 2,
    import_names_operand: 18,
};

struct Stub {
    import_loop: Option<ImportLoop>,
    recognised: bool,       // false: core loop only
    marks_completion: bool, // upx >= 1.94 clears upx0 write flag last
}

struct ImportLoop {
    list: usize,
    names: usize,
}

struct StoredHeaders {
    offset: usize,
    length: usize,
}

struct RelocationStream {
    start: usize,
    flags: u8,
}

struct ExtraFields {
    import_list: Option<usize>,
    relocations: Option<RelocationStream>,
    exact: Option<u32>,
}

struct ListedModule {
    name_offset: usize,
    iat_offset: usize,
    functions: Vec<ImportedFunction>,
}

fn unpack(image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
    let model = image.model();
    let bytes = image.bytes();
    let image_start = model.sections.first()?.virtual_address().as_usize();
    let stub = find_stub(bytes, model);
    let pack_header = find_pack_header(bytes);

    if stub.is_none() && pack_header.is_none() {
        return None;
    }

    let file = origin.read_file();
    let version = pack_header
        .as_ref()
        .and_then(|header| header.version.clone())
        .or_else(|| find_pack_header(file?)?.version); // header overwritten in memory

    let marked = stub_finished(model);
    let expects_completion_mark = stub.as_ref().is_some_and(|stub| stub.marks_completion)
        && matches!(origin.headers, HeaderSource::Memory);
    let ready = marked || (!expects_completion_mark && first_section_filled(bytes, model));

    let outcome = match ready {
        true => restore(
            image,
            stub.as_ref(),
            pack_header.as_ref(),
            image_start,
            marked,
            version.clone(),
        ),
        false => Err(Refusal("the stub had not finished unpacking")),
    };

    match outcome {
        Ok(mut unpacked) => {
            if let (Some(restored), Some(file)) = (unpacked.image.as_deref(), file) {
                unpacked.fresh = fresh(bytes, restored, file, origin.base, image_start);
            }
            Some(unpacked)
        }
        Err(refusal) => stub
            .is_some_and(|stub| stub.recognised)
            .then(|| Unpacked::refused(NAME, version, refusal)),
    }
}

fn stub_finished(model: &PeModel) -> bool {
    model
        .sections
        .first()
        .is_some_and(|section| section.characteristics() & IMAGE_SCN_MEM_WRITE == 0)
}

fn first_section_filled(bytes: &[u8], model: &PeModel) -> bool {
    model.sections.first().is_some_and(|section| {
        let start = section.virtual_address().as_usize();
        let end = start
            .saturating_add(section.mapped_size() as usize)
            .min(bytes.len());
        bytes
            .get(start..end)
            .is_some_and(|data| data.iter().any(|&byte| byte != 0)) // upx0 zero until stub runs
    })
}

fn restore(
    image: &PeImage<'_>,
    stub: Option<&Stub>,
    pack_header: Option<&PackHeader>,
    image_start: usize,
    marked: bool,
    version: Option<String>,
) -> Step<Unpacked> {
    let bytes = image.bytes();
    let stub_list = stub
        .and_then(|stub| stub.import_loop.as_ref())
        .map(|import_loop| import_loop.list);
    let names = import_names(image, stub, image_start);
    let from_pack_header =
        pack_header.and_then(|header| headers_from_pack_header(bytes, header, image_start));
    let after_import_list =
        stub_list.and_then(|list| headers_after_import_list(bytes, list, image_start));
    let scanned = stub
        .into_iter()
        .flat_map(|_| scan_for_stored_headers(bytes, image_start));

    let mut refusal = Refusal("no stored headers were found");
    let candidates = from_pack_header
        .into_iter()
        .chain(after_import_list)
        .chain(scanned);
    for (tried, stored) in candidates.enumerate() {
        if tried == MAX_STORED_CANDIDATES {
            return Err(Refusal(
                "too many stored header candidates, and none of the first ones fits",
            ));
        }

        if !matches_running_image(bytes, stored.offset, image.model()) {
            refusal = Refusal("stored headers were found, but none matches the running image");
            continue;
        }

        match restore_from(
            image,
            &stored,
            image_start,
            stub_list,
            names,
            marked,
            version.clone(),
        ) {
            Ok(unpacked) => return Ok(unpacked),
            Err(why) => refusal = why,
        }
    }

    Err(refusal)
}

fn restore_from(
    image: &PeImage<'_>,
    stored: &StoredHeaders,
    image_start: usize,
    stub_list: Option<usize>,
    names: Option<usize>,
    marked: bool,
    version: Option<String>,
) -> Step<Unpacked> {
    let model = image.model();
    let mut restored = image.bytes().to_vec();
    let written = write_stored_headers(&mut restored, model.nt_offset, stored, image_start);
    need(
        written,
        "the stored headers did not fit over the running ones",
    )?;

    let parsed = parse_memory_image(&restored).ok();
    let restored_model = need(parsed, "the stored headers do not parse")?.into_model();
    let extra = read_extra_fields(
        &restored,
        &restored_model,
        stored,
        image_start,
        stub_list,
        names,
    );
    let extra = need(
        extra,
        "the extra fields after the stored headers do not match the stub",
    )?;

    if !marked {
        let filled = extra
            .import_list
            .zip(names)
            .and_then(|(list, names)| parse_import_list(image.bytes(), list, names, image_start))
            .is_some_and(|modules| {
                !modules.is_empty() && iat_filled(image.bytes(), &modules, model.kind, false)
            });
        if !filled {
            return Err(Refusal(
                "the stub left no completion mark and its import list is not all resolved",
            ));
        }
    }

    let mut report = PackerReport::new(NAME, version);
    report.restored(Part::Headers);

    let entry = read_u32(&restored, restored_model.entry_point_offset).ok();
    if need(entry, "the stored entry point cannot be read")? != 0 {
        report.restored(Part::EntryPoint);
    }

    let imports = restore_imports(image.bytes(), names, &extra, image_start, &mut report);

    if !matches!(imports, PackerImports::Intact) {
        restored_model.clear_directory(&mut restored, BOUND_IMPORT_DIRECTORY);
    }

    let relocations = restore_relocations(&mut restored, &restored_model, &extra, image_start);
    report.record(Part::Relocations, relocations);

    let exports = restore_exports(&mut restored, &restored_model, image);
    report.record(Part::Exports, exports);

    let resources = restore_resources(&mut restored, &restored_model, image, image_start);
    report.record(Part::Resources, resources);

    restore_debug_directory(&mut restored, &restored_model, stored, &mut report);
    if guard_flags_cleared(&restored, &restored_model) {
        report.lost(Part::GuardFlags);
    }

    Unpacked::restored(restored, report, Some(imports), None)
}

fn import_names(image: &PeImage<'_>, stub: Option<&Stub>, image_start: usize) -> Option<usize> {
    stub.and_then(|stub| stub.import_loop.as_ref())
        .map(|import_loop| import_loop.names)
        .or_else(|| {
            let directory = image.directory(IMPORT_DIRECTORY)?;
            directory.rva().as_usize().checked_sub(image_start)
        })
}

fn restore_imports(
    bytes: &[u8],
    names: Option<usize>,
    extra: &ExtraFields,
    image_start: usize,
    report: &mut PackerReport,
) -> PackerImports {
    let Some(list) = extra.import_list else {
        return PackerImports::Intact;
    };

    if extra.exact.is_some() {
        report.restored(Part::Imports);
        return PackerImports::Intact;
    }

    match names.and_then(|names| parse_import_list(bytes, list, names, image_start)) {
        Some(modules) => {
            report.restored(Part::Imports);
            PackerImports::Listed(modules)
        }
        None => {
            report.failed_with(
                Part::Imports,
                "the packer's list was unreadable, so they come from the filled IAT",
            );
            PackerImports::Unknown
        }
    }
}

fn find_stub(bytes: &[u8], model: &PeModel) -> Option<Stub> {
    let shape = match model.kind {
        PeKind::Pe32Plus => &X64_STUB,
        PeKind::Pe32 => &X86_STUB,
    };

    let entry = Rva(read_u32(bytes, model.entry_point_offset).ok()?);
    let sections = &model.sections;
    let entry_section = sections.iter().find(|section| section.contains_rva(entry));
    let other_code = sections
        .iter()
        .filter(|section| section.is_executable() && !section.contains_rva(entry));
    entry_section
        .into_iter()
        .chain(other_code)
        .find_map(|section| stub_in_section(bytes, section, shape))
}

fn stub_in_section(bytes: &[u8], section: &SectionModel, shape: &StubPatterns) -> Option<Stub> {
    let Range { start, end } = section.range_in(bytes);
    let code = bytes.get(start..end)?;

    let import_loop = find_pattern(code, shape.import_loop).and_then(|at| {
        let operand = |offset: usize| -> Option<usize> {
            let at = start.checked_add(at)?.checked_add(offset)?;
            Some(read_u32(bytes, at).ok()? as usize)
        };

        Some(ImportLoop {
            list: operand(shape.import_list_operand)?,
            names: operand(shape.import_names_operand)?,
        })
    });

    let stack_clear_core = find_pattern(code, shape.stack_clear_core).is_some();
    let stack_clear = stack_clear_core && find_pattern(code, shape.stack_clear).is_some();

    if import_loop.is_none() && !stack_clear_core {
        return None;
    }

    Some(Stub {
        recognised: import_loop.is_some() || stack_clear,
        marks_completion: stack_clear_core,
        import_loop,
    })
}

fn parse_import_list(
    bytes: &[u8],
    list: usize,
    names: usize,
    image_start: usize,
) -> Option<Vec<ModuleImports>> {
    let (modules, _) = read_import_list(bytes, image_start.checked_add(list)?)?;
    modules
        .into_iter()
        .map(|listed| {
            let name_at = image_start
                .checked_add(names)?
                .checked_add(listed.name_offset)?;
            Some(ModuleImports {
                module: Some(read_c_string(bytes, name_at)?.0),
                first_thunk: u32::try_from(image_start.checked_add(listed.iat_offset)?).ok()?,
                functions: listed.functions,
            })
        })
        .collect()
}

fn read_import_list(bytes: &[u8], start: usize) -> Option<(Vec<ListedModule>, usize)> {
    let mut modules = Vec::new();
    let mut at = start;

    while modules.len() < MAX_IMPORT_DESCRIPTORS {
        let name_offset = read_u32(bytes, at).ok()? as usize;

        if name_offset == 0 {
            return Some((modules, at.checked_add(4)?));
        }

        let iat_offset = read_u32(bytes, at.checked_add(MODULE_IAT_OFFSET)?).ok()? as usize;
        let (functions, next) = parse_import_functions(bytes, at.checked_add(MODULE_HEADER_SIZE)?)?;
        modules.push(ListedModule {
            name_offset,
            iat_offset,
            functions,
        });

        at = next;
    }

    None
}

fn parse_import_functions(bytes: &[u8], start: usize) -> Option<(Vec<ImportedFunction>, usize)> {
    let mut functions = Vec::new();
    let mut at = start;

    while functions.len() < MAX_IMPORTS {
        match *bytes.get(at)? {
            0 => return Some((functions, at.checked_add(1)?)),
            IMPORT_BY_NAME => {
                let (name, next) = read_c_string(bytes, at.checked_add(1)?)?;
                functions.push(ImportedFunction::Name(name));
                at = next;
            }
            IMPORT_BY_ORDINAL => {
                functions.push(ImportedFunction::Ordinal(
                    read_u16(bytes, at.checked_add(1)?).ok()?,
                ));
                at = at.checked_add(ORDINAL_RECORD_SIZE)?;
            }
            IMPORT_KERNEL32_THUNK => {
                functions.push(ImportedFunction::OrdinalFromAddress);
                at = at.checked_add(THUNK_RECORD_SIZE)?;
            }
            _ => return None,
        }
    }

    None
}

struct PackHeader {
    offset: usize,
    version: Option<String>,
    uncompressed_length: usize,
}

fn find_pack_header(bytes: &[u8]) -> Option<PackHeader> {
    pack_header_where(bytes, |header| {
        header.starts_with(PACK_HEADER_MAGIC) && header_checks(header)
    })
}

fn pack_header_where(bytes: &[u8], fits: impl Fn(&[u8]) -> bool) -> Option<PackHeader> {
    let window = bytes.get(..PACK_HEADER_WINDOW.min(bytes.len()))?;
    let at = unique(
        window
            .windows(PACK_HEADER_SIZE)
            .enumerate()
            .filter(|(_, header)| fits(header))
            .map(|(at, _)| at),
    )?;
    pack_header_at(bytes, at)
}

fn header_checks(header: &[u8]) -> bool {
    let Some((checksum, summed)) = header
        .get(CHECKSUM_START..PACK_HEADER_SIZE)
        .and_then(<[u8]>::split_last)
    else {
        return false;
    };
    let sum = summed.iter().map(|&byte| u32::from(byte)).sum::<u32>();

    header
        .get(FORMAT_OFFSET)
        .is_some_and(|format| PE_FORMATS.contains(format))
        && header
            .get(METHOD_OFFSET)
            .is_some_and(|method| METHODS.contains(method))
        && sum % CHECKSUM_MODULO == u32::from(*checksum)
}

fn pack_header_at(bytes: &[u8], magic: usize) -> Option<PackHeader> {
    let uncompressed_length =
        read_u32(bytes, magic.checked_add(UNCOMPRESSED_LENGTH_OFFSET)?).ok()? as usize;
    let version = magic
        .checked_sub(VERSION_LENGTH + 1)
        .and_then(|start| bytes.get(start..start + VERSION_LENGTH))
        .filter(|text| {
            text.iter()
                .all(|byte| byte.is_ascii_digit() || *byte == b'.')
        })
        .and_then(|text| std::str::from_utf8(text).ok())
        .map(str::to_owned);
    Some(PackHeader {
        offset: magic,
        version,
        uncompressed_length,
    })
}

fn same_image(memory: &[u8], file: &[u8], disk: &PeModel) -> bool {
    let Ok(running) = parse_memory_image(memory) else {
        return false;
    };
    let running = running.model();
    let field = |bytes: &[u8], offset: usize| read_u32(bytes, offset).ok();

    running.kind == disk.kind
        && running.image_size == disk.image_size
        && running.sections.len() == disk.sections.len()
        && field(memory, running.entry_point_offset) == field(file, disk.entry_point_offset)
        && field(memory, running.nt_offset + TIMESTAMP_OFFSET)
            == field(file, disk.nt_offset + TIMESTAMP_OFFSET)
}

fn fresh(
    memory: &[u8],
    restored: &[u8],
    file: &[u8],
    base: usize,
    image_start: usize,
) -> Option<FreshCopy> {
    let header = find_pack_header(file).or_else(|| pack_header_where(file, header_checks))?; // magic wiped
    let field = |offset| read_u32(file, header.offset + offset).ok();
    let packed_length = field(COMPRESSED_LENGTH_OFFSET)? as usize;
    let packed_adler = field(COMPRESSED_ADLER_OFFSET)?;

    let disk = parse_disk_image(file).ok()?;
    same_image(memory, file, disk.model()).then_some(())?;
    let file_base = file_base(file, disk.model())?;
    let after_header = header.offset + PACK_HEADER_SIZE; // small files: header precedes stream
    let stream = disk
        .model()
        .sections
        .iter()
        .flat_map(|section| [section.raw_pointer as usize, after_header])
        .filter_map(|start| file.get(start..start.checked_add(packed_length)?))
        .find(|stream| adler32(stream) == packed_adler)?;

    let size = header.uncompressed_length;
    (image_start.checked_add(size)? <= memory.len()).then_some(())?; // in place unpack
    let data = match *file.get(header.offset + METHOD_OFFSET)? {
        METHOD_NRV2B => nrv::decompress(stream, size, Variant::B).ok(),
        METHOD_NRV2D => nrv::decompress(stream, size, Variant::D).ok(),
        METHOD_NRV2E => nrv::decompress(stream, size, Variant::E).ok(),
        METHOD_LZMA => decompress_lzma(stream, size),
        _ => None,
    }?;
    (adler32(&data) == field(UNCOMPRESSED_ADLER_OFFSET)?).then_some(())?;

    let mut pristine = vec![0; image_start];
    pristine.extend(data);

    let model = parse_memory_image(restored).ok()?.into_model();
    let stored = |value: usize, kind| match kind {
        PeKind::Pe32 => (value as u32).swap_bytes() as usize,
        PeKind::Pe32Plus => (value as u64).swap_bytes() as usize,
    }; // big endian, first section relative
    let decoded = relocate(&mut pristine, restored, &model, |value, kind| {
        stored(value, kind)
            .wrapping_add(image_start)
            .wrapping_add(file_base)
    });
    (decoded.is_some() || relocations_stripped(restored, &model)).then_some(())?;

    let mut filtered = Vec::new();
    if *file.get(header.offset + FILTER_OFFSET)? != 0 {
        let code_size = read_u32(restored, model.size_of_code_offset).ok()? as usize;
        let code_base = read_u32(restored, model.base_of_code_offset).ok()? as usize;
        filtered.push(code_base..code_base.saturating_add(code_size)); // filtered code not rebuilt
    }

    with_initial_data(
        memory,
        restored,
        InitialData {
            bytes: &pristine,
            base: file_base,
        },
        base,
        restored.len(),
        &filtered,
    )
}

fn decompress_lzma(stream: &[u8], size: usize) -> Option<Vec<u8>> {
    let [positions, literals, ..] = *stream else {
        return None;
    };

    let properties = lzma::Properties {
        literal_context: literals & LZMA_LITERAL_CONTEXT_MASK,
        literal_position: literals >> LZMA_LITERAL_POSITION_SHIFT,
        position: positions & LZMA_POSITION_MASK,
    };
    lzma::decompress(stream.get(LZMA_HEADER..)?, &properties, size).ok()
}

fn adler32(bytes: &[u8]) -> u32 {
    const BLOCK: usize = 5_552; // adler: most bytes before u32 overflow

    let (mut low, mut high) = (1u32, 0u32);
    for block in bytes.chunks(BLOCK) {
        for byte in block {
            low += u32::from(*byte);
            high += low;
        }
        low %= ADLER_MODULO;
        high %= ADLER_MODULO;
    }
    (high << 16) | low
}

fn headers_from_pack_header(
    bytes: &[u8],
    header: &PackHeader,
    image_start: usize,
) -> Option<StoredHeaders> {
    let trailer = image_start
        .checked_add(header.uncompressed_length)?
        .checked_sub(EXTRA_INFO_OFFSET_SIZE)?;
    let offset = read_u32(bytes, trailer).ok()? as usize;
    stored_headers_at(bytes, image_start.checked_add(offset)?, image_start)
}

fn headers_after_import_list(
    bytes: &[u8],
    list: usize,
    image_start: usize,
) -> Option<StoredHeaders> {
    let list_end = read_import_list(bytes, image_start.checked_add(list)?)?.1;
    let relocation_end = walk_relocations(bytes, list_end).map(|walk| walk.1);
    [Some(list_end), relocation_end]
        .into_iter()
        .flatten()
        .find_map(|start| {
            (start..start.saturating_add(EXTRA_INFO_SCAN))
                .find_map(|offset| stored_headers_at(bytes, offset, image_start))
        })
}

fn scan_for_stored_headers(
    bytes: &[u8],
    image_start: usize,
) -> impl Iterator<Item = StoredHeaders> + '_ {
    bytes
        .get(image_start..)
        .unwrap_or_default()
        .windows(PE_SIGNATURE.len())
        .enumerate()
        .filter(|(_, window)| window == PE_SIGNATURE)
        .filter_map(move |(offset, _)| {
            stored_headers_at(bytes, image_start.checked_add(offset)?, image_start)
        })
}

fn stored_headers_at(bytes: &[u8], offset: usize, image_start: usize) -> Option<StoredHeaders> {
    if bytes.get(offset..offset.checked_add(PE_SIGNATURE.len())?)? != PE_SIGNATURE {
        return None;
    }

    let optional_size =
        usize::from(read_u16(bytes, offset.checked_add(OPTIONAL_SIZE_OFFSET)?).ok()?);
    let sections = usize::from(read_u16(bytes, offset.checked_add(SECTION_COUNT_OFFSET)?).ok()?);
    let table = offset
        .checked_add(FILE_HEADER_END)?
        .checked_add(optional_size)?;
    let first_section = read_u32(bytes, table.checked_add(SECTION_RVA_OFFSET)?).ok()? as usize;

    if sections == 0 || first_section != image_start {
        return None;
    }

    let length = table
        .checked_add(sections.checked_mul(SECTION_HEADER_SIZE)?)?
        .checked_sub(offset)?;
    bytes.get(offset..offset.checked_add(length)?)?;

    Some(StoredHeaders { offset, length })
}

fn matches_running_image(bytes: &[u8], offset: usize, model: &PeModel) -> bool {
    let machine = match model.kind {
        PeKind::Pe32 => MACHINE_I386,
        PeKind::Pe32Plus => MACHINE_AMD64,
    };
    let field = |at: usize| offset.checked_add(at);

    field(MACHINE_OFFSET).and_then(|at| read_u16(bytes, at).ok()) == Some(machine)
        && field(FILE_HEADER_END + SECTION_ALIGNMENT_OFFSET).and_then(|at| read_u32(bytes, at).ok())
            == Some(model.section_alignment)
}

fn write_stored_headers(
    restored: &mut [u8],
    nt_offset: usize,
    stored: &StoredHeaders,
    image_start: usize,
) -> Option<()> {
    let end = nt_offset.checked_add(stored.length)?;

    if end > image_start {
        return None;
    }

    let headers = restored
        .get(stored.offset..stored.offset.checked_add(stored.length)?)?
        .to_vec();
    restored.get_mut(nt_offset..end)?.copy_from_slice(&headers);
    restored.get_mut(end..image_start)?.fill(0);

    Some(())
}

fn read_extra_fields(
    restored: &[u8],
    model: &PeModel,
    stored: &StoredHeaders,
    image_start: usize,
    stub_list: Option<usize>,
    names: Option<usize>,
) -> Option<ExtraFields> {
    let mut cursor = stored.offset.checked_add(stored.length)?;
    let mut import_list = None;

    if model.directory(restored, IMPORT_DIRECTORY).is_some() {
        let listed = read_u32(restored, cursor).ok()? as usize;

        if stub_list.is_some_and(|list| list != listed) {
            return None;
        }

        import_list = Some(listed);
        cursor = cursor.checked_add(IMPORT_FIELDS_SIZE)?;
    }

    let confirmed_by_imports = import_list.is_some_and(|list| {
        stub_list.is_some()
            || names.is_some_and(|names| {
                parse_import_list(restored, list, names, image_start)
                    .is_some_and(|modules| !modules.is_empty())
            })
    });

    let mut relocations = None;
    if model.directory(restored, BASERELOC_DIRECTORY).is_some()
        && !relocations_stripped(restored, model)
    {
        let start = image_start.checked_add(read_u32(restored, cursor).ok()? as usize)?;
        let stream_flags = *restored.get(cursor.checked_add(RELOCATION_FLAGS_OFFSET)?)?;
        relocations = Some(RelocationStream {
            start,
            flags: stream_flags,
        });

        cursor = cursor.checked_add(RELOCATION_FIELDS_SIZE)?;
    }

    let offset_field = u32::try_from(stored.offset.checked_sub(image_start)?).ok()?;
    let with_icons = cursor.checked_add(ICON_COUNT_SIZE)?;
    let candidates = match model.directory(restored, RESOURCE_DIRECTORY).is_some() {
        true => [with_icons, cursor],
        false => [cursor, cursor],
    };

    if candidates
        .iter()
        .any(|end| read_u32(restored, *end).ok() == Some(offset_field))
    {
        return Some(ExtraFields {
            import_list,
            relocations,
            exact: None,
        });
    }

    let exact = candidates
        .iter()
        .find_map(|end| exact_trailer(restored, *end, offset_field));
    if exact.is_none() && !confirmed_by_imports {
        return None;
    }

    Some(ExtraFields {
        import_list,
        relocations: relocations.filter(|stream| {
            exact.is_some() || stream_end(restored, stream) == Some(stored.offset) // the trailer may be overwritten at run time
        }),
        exact,
    })
}

fn exact_trailer(restored: &[u8], fields_end: usize, offset_field: u32) -> Option<u32> {
    (0..MAX_EXACT_GAP).find_map(|gap| {
        let trailer = fields_end.checked_add(gap)?;
        let stored_gap = read_u32(restored, trailer.checked_add(EXACT_GAP_OFFSET)?).ok()? as usize;
        let offset = read_u32(restored, trailer.checked_add(EXACT_TRAILER)?).ok()?;
        (stored_gap == gap && offset == offset_field)
            .then(|| read_u32(restored, trailer).ok())
            .flatten()
    })
}

fn walk_relocations(bytes: &[u8], start: usize) -> Option<(Vec<usize>, usize)> {
    let mut positions = Vec::new();
    let mut position = RELOCATION_STREAM_ORIGIN;
    let mut at = start;

    while positions.len() < MAX_RELOCATIONS {
        let lead = *bytes.get(at)?;
        at = at.checked_add(1)?;

        let delta = match lead {
            0 => return Some((positions, at)),
            LONG_DELTA if bytes.get(at..at.checked_add(2)?)? == [0, 0] => {
                let delta = read_u32(bytes, at.checked_add(2)?).ok()? as usize; // after f0 00 00
                at = at.checked_add(6)?;
                delta
            }
            lead if lead >= LONG_DELTA => {
                let low = usize::from(*bytes.get(at)?);
                let middle = usize::from(*bytes.get(at.checked_add(1)?)?);
                at = at.checked_add(2)?;
                (usize::from(lead & LONG_DELTA_HIGH_BITS) << 16) | (middle << 8) | low
            }
            lead => usize::from(lead),
        };

        position = position.checked_add_unsigned(delta)?;
        positions.push(usize::try_from(position).ok()?);
    }

    None
}

fn sixteen_bit_relocations(
    bytes: &[u8],
    start: usize,
    flags: u8,
) -> Option<(Vec<(usize, u16)>, usize)> {
    let mut lists = Vec::new();

    if flags & LOW_LIST != 0 {
        lists.push(RELOCATION_LOW);
    }

    if flags & HIGH_LIST != 0 {
        lists.push(RELOCATION_HIGH);
    }

    let mut entries = Vec::new();
    let mut at = start;

    for kind in lists {
        loop {
            let offset = read_u32(bytes, at).ok()? as usize;
            at = at.checked_add(4)?;

            if offset == 0 {
                break;
            }

            if entries.len() >= MAX_RELOCATIONS {
                return None;
            }

            entries.push((offset, kind));
        }
    }

    Some((entries, at))
}

// upx lays the relocations out right after the import data and its extra fields right after them
fn stream_end(bytes: &[u8], stream: &RelocationStream) -> Option<usize> {
    let (_, end) = walk_relocations(bytes, stream.start)?;
    sixteen_bit_relocations(bytes, end, stream.flags).map(|(_, end)| end)
}

fn decode_relocations(
    bytes: &[u8],
    stream: &RelocationStream,
    kind: u16,
    image_start: usize,
) -> Option<Vec<(u32, u16)>> {
    let (positions, end) = walk_relocations(bytes, stream.start)?;
    let (sixteen_bit, _) = sixteen_bit_relocations(bytes, end, stream.flags)?;

    positions
        .into_iter()
        .map(|offset| (offset, kind))
        .chain(sixteen_bit)
        .map(|(offset, kind)| Some((u32::try_from(image_start.checked_add(offset)?).ok()?, kind)))
        .collect()
}

fn relocations_stripped(restored: &[u8], model: &PeModel) -> bool {
    read_u16(restored, model.nt_offset + FILE_CHARACTERISTICS_OFFSET)
        .is_ok_and(|flags| flags & RELOCS_STRIPPED != 0)
}

fn restore_relocations(
    restored: &mut [u8],
    model: &PeModel,
    extra: &ExtraFields,
    image_start: usize,
) -> Restoration {
    let Some(directory) = model.directory(restored, BASERELOC_DIRECTORY) else {
        return Restoration::Absent;
    };

    if relocations_stripped(restored, model) {
        model.clear_directory(restored, BASERELOC_DIRECTORY);
        return Restoration::Lost;
    }

    let start = directory.rva().as_usize();
    let size = directory.size() as usize;
    let rebuilds = extra
        .exact
        .is_none_or(|flags| flags & EXACT_RELOCATIONS != 0);
    if relocations_intact(restored, start, size) || !rebuilds {
        return Restoration::Restored;
    }

    if size == EMPTY_RELOCATION_BLOCK.len() {
        return match place(restored, start, &EMPTY_RELOCATION_BLOCK) {
            Some(()) => Restoration::Restored,
            None => Restoration::Failed,
        };
    }

    let kind = model.kind.relocation_type();

    let rebuilt = extra
        .relocations
        .as_ref()
        .and_then(|stream| decode_relocations(restored, stream, kind, image_start))
        .and_then(|entries| relocation_blocks(&entries))
        .filter(|blocks| blocks.len() <= size)
        .and_then(|blocks| place(restored, start, &blocks).map(|()| blocks.len()))
        .and_then(|length| model.set_directory(restored, BASERELOC_DIRECTORY, start, length))
        .map(|()| Restoration::Restored);
    restored_or_cleared(restored, model, BASERELOC_DIRECTORY, rebuilt)
}

fn restore_exports(restored: &mut [u8], model: &PeModel, packed: &PeImage<'_>) -> Restoration {
    let Some(original) = model.directory(restored, EXPORT_DIRECTORY) else {
        return Restoration::Absent;
    };

    let destination = original.rva().as_usize();

    if exports_intact(restored, destination) {
        return Restoration::Restored;
    }

    let moved = packed.directory(EXPORT_DIRECTORY).and_then(|copy| {
        let size = copy.size() as usize;
        let block =
            moved_export_directory(packed.bytes(), copy.rva().as_usize(), size, destination)?;
        place(restored, destination, &block)?;
        model.set_directory(restored, EXPORT_DIRECTORY, destination, block.len())?;
        Some(match linker_order(restored, destination, block.len()) {
            true => Restoration::Inferred("forwarder strings ordered as the linker lays them"),
            false => Restoration::Restored,
        })
    });
    restored_or_cleared(restored, model, EXPORT_DIRECTORY, moved)
}

fn linker_order(restored: &mut [u8], start: usize, size: usize) -> bool {
    let end = start.saturating_add(size);
    let forwarders = export_forwarders(restored, start, |rva| (start..end).contains(&rva));
    if forwarders.is_empty() {
        return false; // only forwarders move
    }

    let Some((_, block)) = linker_export_layout(restored, start, &forwarders, Some(start)) else {
        return false;
    };
    match restored.get_mut(start..end).filter(|_| block.len() == size) {
        Some(target) => {
            target.copy_from_slice(&block);
            true
        }
        None => false,
    }
}

fn guard_flags_cleared(restored: &[u8], model: &PeModel) -> bool {
    let Some(directory) = model.directory(restored, LOAD_CONFIG_DIRECTORY) else {
        return false;
    };
    let start = directory.rva().as_usize();
    let (count, flags) = match model.kind {
        PeKind::Pe32 => (GUARD_FUNCTION_COUNT_PE32, GUARD_FLAGS_PE32),
        PeKind::Pe32Plus => (GUARD_FUNCTION_COUNT_PE32_PLUS, GUARD_FLAGS_PE32_PLUS),
    };
    let field = |offset: usize| read_u32(restored, start.saturating_add(offset)).ok();

    field(0).is_some_and(|size| size as usize >= flags + 4)
        && field(count).is_some_and(|count| count != 0)
        && field(flags).is_some_and(|flags| flags & GUARD_CF_INSTRUMENTED == 0) // upx --force
}

fn restore_resources(
    restored: &mut [u8],
    model: &PeModel,
    packed: &PeImage<'_>,
    image_start: usize,
) -> Restoration {
    let Some(destination) = model.directory(restored, RESOURCE_DIRECTORY) else {
        return Restoration::Absent;
    };

    let rva = destination.rva().as_usize();
    let tree = packed_resources(packed, image_start);

    if resources_intact(restored, rva) {
        let missed = tree
            .as_ref()
            .map_or(0, |tree| tree.return_kept_leaves(restored, rva));
        return match missed {
            0 => Restoration::Restored,
            _ => Restoration::Failed,
        };
    }

    let moved = tree.and_then(|tree| {
        if !tree.fits(restored, rva, destination.size() as usize) {
            return None;
        }

        tree.apply(restored, rva)?;
        Some(Restoration::Restored)
    });

    restored_or_cleared(restored, model, RESOURCE_DIRECTORY, moved)
}

fn restore_debug_directory(
    restored: &mut [u8],
    model: &PeModel,
    stored: &StoredHeaders,
    report: &mut PackerReport,
) {
    let Some(directory) = model.directory(restored, DEBUG_DIRECTORY) else {
        return;
    };

    let start = directory.rva().as_usize();
    let Some(table) = restored.get(start..start.saturating_add(directory.size() as usize)) else {
        return;
    };

    let entries = table.as_chunks::<DEBUG_ENTRY_SIZE>().0;
    let is_erased = |entry: &&[u8; DEBUG_ENTRY_SIZE]| entry.iter().all(|byte| *byte == 0);
    let erased = entries.iter().filter(is_erased).count();

    if erased == 0 {
        report.restored(Part::DebugDirectory);
        return;
    }

    let mut kept = entries
        .iter()
        .filter(|entry| !is_erased(entry))
        .copied()
        .collect::<Vec<_>>(); // upx >= 5.1 keeps cet entry
    let has_codeview = kept
        .iter()
        .any(|entry| read_u32(entry, DEBUG_TYPE_OFFSET).ok() == Some(DEBUG_TYPE_CODEVIEW));
    let timestamp = read_u32(restored, stored.offset.saturating_add(TIMESTAMP_OFFSET)).unwrap_or(0);
    let codeview = match has_codeview {
        true => None,
        false => {
            find_codeview_record(restored).and_then(|record| codeview_entry(&record, timestamp))
        }
    };

    kept.extend(codeview);

    let rebuilt = kept.concat();

    let table_length = table.len();
    let written = restored
        .get_mut(start..start.saturating_add(table_length))
        .and_then(|table| {
            table.fill(0);
            table.get_mut(..rebuilt.len())?.copy_from_slice(&rebuilt);
            Some(())
        });
    match written {
        Some(()) if !rebuilt.is_empty() => {
            let _ = model.set_directory(restored, DEBUG_DIRECTORY, start, rebuilt.len());
            match codeview {
                Some(_) => report.inferred(
                    Part::DebugDirectory,
                    "CodeView entry rebuilt from the only record in the image",
                ),
                None => report.restored(Part::DebugDirectory),
            }
        }
        _ => _ = model.clear_directory(restored, DEBUG_DIRECTORY),
    }

    if erased > usize::from(codeview.is_some()) {
        report.lost(Part::DebugEntries);
    }
}

struct PackedResources<'a> {
    bytes: &'a [u8],
    start: usize,
    structure_length: usize,
    leaves: Vec<ResourceLeaf>,
}

struct ResourceLeaf {
    entry: usize,
    rva: usize,
    size: usize,
    original: Option<usize>,
}

fn packed_resources<'a>(packed: &PeImage<'a>, image_start: usize) -> Option<PackedResources<'a>> {
    let directory = packed.directory(RESOURCE_DIRECTORY)?;
    let start = directory.rva().as_usize();
    let section_end = packed
        .model()
        .sections
        .iter()
        .find(|section| section.contains_rva(directory.rva()))?
        .range()
        .end;

    let bytes = packed.bytes();
    let tree = walk_resources(bytes, start)?;
    let leaves = tree
        .data_entries
        .into_iter()
        .map(|entry| {
            let (_, rva, size) = resource_leaf(bytes, start, entry)?;
            let kept_by_packer = (start..section_end).contains(&rva);
            let original = match kept_by_packer {
                true => Some(read_u32(bytes, rva.checked_sub(ORIGINAL_RVA_PREFIX)?).ok()? as usize),
                false => None,
            };

            let inside_image = |original: usize| {
                original >= image_start
                    && original
                        .checked_add(size)
                        .is_some_and(|end| end <= bytes.len())
            };

            if original.is_some_and(|original| !inside_image(original)) {
                return None;
            }

            Some(ResourceLeaf {
                entry,
                rva,
                size,
                original,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(PackedResources {
        bytes,
        start,
        structure_length: tree.structure_length,
        leaves,
    })
}

impl PackedResources<'_> {
    fn structure(&self) -> Option<&[u8]> {
        self.bytes
            .get(self.start..self.start.checked_add(self.structure_length)?)
    }

    fn fits(&self, restored: &[u8], destination: usize, size: usize) -> bool {
        let Some(structure) = self.structure() else {
            return false;
        };

        let Some(end) = destination.checked_add(structure.len()) else {
            return false;
        };

        let overlaps_leaf = self.leaves.iter().any(|leaf| {
            let start = leaf.original.unwrap_or(leaf.rva);
            start < end && destination < start.saturating_add(leaf.size)
        });

        structure.len() <= size && !overlaps_leaf && is_free(restored, destination, structure)
    }

    fn return_kept_leaves(&self, restored: &mut [u8], tree_start: usize) -> usize {
        let Some(tree) = walk_resources(restored, tree_start) else {
            return self.leaves.len();
        };

        let listed = tree
            .data_entries
            .iter()
            .filter_map(|entry| {
                let (_, rva, size) = resource_leaf(restored, tree_start, *entry)?;
                Some((rva, size))
            })
            .collect::<Vec<_>>();
        let mut missed = 0;
        for leaf in &self.leaves {
            let Some(original) = leaf.original else {
                continue;
            };

            if original == leaf.rva || !listed.contains(&(original, leaf.size)) {
                continue;
            }

            let data = self.bytes.get(leaf.rva..leaf.rva.saturating_add(leaf.size));
            let placed = data.and_then(|data| place(restored, original, data));
            missed += usize::from(placed.is_none());
        }

        missed
    }

    fn apply(&self, restored: &mut [u8], destination: usize) -> Option<()> {
        let structure = self.structure()?.to_vec();
        place(restored, destination, &structure)?;

        for leaf in &self.leaves {
            let Some(original) = leaf.original else {
                continue;
            };

            let data = self.bytes.get(leaf.rva..leaf.rva.checked_add(leaf.size)?)?;
            restored
                .get_mut(original..original.checked_add(leaf.size)?)?
                .copy_from_slice(data);
            write_u32(
                restored,
                destination.checked_add(leaf.entry)?,
                u32::try_from(original).ok()?,
            )
            .ok()?;
        }

        Some(())
    }
}

pub(super) struct Upx;

impl Packer for Upx {
    fn unpack(&self, image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
        unpack(image, origin)
    }
}
