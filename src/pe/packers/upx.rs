use super::tables::{
    DEBUG_ENTRY_SIZE, DEBUG_TYPE_CODEVIEW, DEBUG_TYPE_OFFSET, RESOURCE_DATA_SIZE_OFFSET,
    Restoration, SECTION_COUNT_OFFSET, SECTION_RVA_OFFSET, clear_directory, codeview_entry,
    exports_intact, find_codeview_record, is_free, moved_export_directory, place, read_c_string,
    relocation_blocks, relocations_intact, resources_intact, set_directory, walk_resources,
};
use super::{
    HeaderSource, ImportedFunction, ModuleImports, Origin, PackerFindings, PackerImports,
    PackerReport, Unpacked, find_pattern,
};
use crate::pe::image::{read_u16, read_u32, write_u32};
use crate::pe::parse::parse_memory_image;
use crate::pe::{
    BASERELOC_DIRECTORY, BOUND_IMPORT_DIRECTORY, DEBUG_DIRECTORY, EXPORT_DIRECTORY,
    IMAGE_SCN_MEM_WRITE, IMPORT_DIRECTORY, PeImage, PeKind, PeModel, RESOURCE_DIRECTORY, Rva,
    SECTION_HEADER_SIZE, SectionModel,
};

const NAME: &str = "UPX";
const PACK_HEADER_MAGIC: &[u8; 4] = b"UPX!";
const PACK_HEADER_WINDOW: usize = 0x1000; // the header page
const UNCOMPRESSED_LENGTH_OFFSET: usize = 16; // u_len inside the pack header
const VERSION_LENGTH: usize = 4; // "5.30" sits before a nul and the magic
const PE_SIGNATURE: &[u8; 4] = b"PE\0\0";
const FILE_HEADER_END: usize = 24; // signature plus file header
const TIMESTAMP_OFFSET: usize = 8;
const OPTIONAL_SIZE_OFFSET: usize = 20;
const FILE_FLAGS_OFFSET: usize = 22;
const RELOCS_STRIPPED: u16 = 0x0001;
const EXTRA_INFO_SCAN: usize = 0x1000;
const EXTRA_INFO_OFFSET_SIZE: usize = 4; // the u32 that ends extra info and points back at its start
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
const MAX_IMPORT_MODULES: usize = 4_096;
const MAX_IMPORT_FUNCTIONS: usize = 65_536;
const MAX_RELOCATIONS: usize = 1 << 22;
const RELOCATION_STREAM_ORIGIN: isize = -4; // upx counts the first delta from here
const LONG_DELTA: u8 = 0xF0; // marks a 3 or 7 byte relocation delta
const LONG_DELTA_HIGH_BITS: u8 = 0x0F;
const HIGH_LIST: u8 = 2; // x86 16bit relocation lists that follow the stream
const LOW_LIST: u8 = 4;
const REL_BASED_HIGH: u16 = 1;
const REL_BASED_LOW: u16 = 2;
const REL_BASED_HIGHLOW: u16 = 3;
const REL_BASED_DIR64: u16 = 10;
const EMPTY_RELOCATION_BLOCK: [u8; 8] = [0, 0, 0, 0, 8, 0, 0, 0];
const ORIGINAL_RVA_PREFIX: usize = 4; // upx stores each kept leaf after its original rva

struct StubShape {
    stack_clear: &'static str,
    stack_clear_core: &'static str,
    import_loop: &'static str,
    import_list_operand: usize,
    import_names_operand: usize,
}

const X64_STUB: StubShape = StubShape {
    stack_clear: "48 8D 44 24 80 6A 00 48 39 C4 75 F9 48 83 EC 80",
    stack_clear_core: "6A 00 48 39 C4 75 F9",
    import_loop: "48 83 EC 28 48 8D BE ?? ?? ?? ?? 8B 07 09 C0 74 ?? 8B 5F 04 48 8D 8C 30 ?? ?? ?? ??",
    import_list_operand: 7,
    import_names_operand: 24,
};

const X86_STUB: StubShape = StubShape {
    stack_clear: "8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80",
    stack_clear_core: "6A 00 39 C4 75 FA",
    import_loop: "8D BE ?? ?? ?? ?? 8B 07 09 C0 74 ?? 8B 5F 04 8D 84 30 ?? ?? ?? ??",
    import_list_operand: 2,
    import_names_operand: 18,
};

struct Stub {
    import_loop: Option<ImportLoop>,
    recognised: bool,       // false when only the bare stack clearing loop matched
    marks_completion: bool, // stubs since upx 1.94 clear upx0's write flag as their last step
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

pub(super) fn unpack(image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
    let model = image.model();
    let bytes = image.bytes();
    let image_start = model.sections().first()?.virtual_address().as_usize();
    let stub = find_stub(bytes, model);
    let pack_header = find_pack_header(bytes);

    if stub.is_none() && pack_header.is_none() {
        return None;
    }

    let version = pack_header
        .as_ref()
        .and_then(|header| header.version.clone());

    let expects_completion_mark = stub.as_ref().is_some_and(|stub| stub.marks_completion)
        && matches!(origin.headers, HeaderSource::Memory);
    let ready = stub_finished(model) || !expects_completion_mark;

    if ready {
        let restored = restore(
            image,
            stub.as_ref(),
            pack_header.as_ref(),
            image_start,
            version.clone(),
        );

        if restored.is_some() {
            return restored;
        }
    }

    if !stub.is_some_and(|stub| stub.recognised) {
        return None;
    }

    let reason = match ready {
        true => "image (its stored headers were not found)",
        false => "image (the stub had not finished unpacking)",
    };

    Some(Unpacked::detected_only(NAME, version, reason))
}

fn stub_finished(model: &PeModel) -> bool {
    model
        .sections()
        .first()
        .is_some_and(|section| section.characteristics() & IMAGE_SCN_MEM_WRITE == 0)
}

fn restore(
    image: &PeImage<'_>,
    stub: Option<&Stub>,
    pack_header: Option<&PackHeader>,
    image_start: usize,
    version: Option<String>,
) -> Option<Unpacked> {
    let bytes = image.bytes();
    let stub_list = stub
        .and_then(|stub| stub.import_loop.as_ref())
        .map(|import_loop| import_loop.list);
    let from_pack_header =
        pack_header.and_then(|header| headers_from_pack_header(bytes, header, image_start));
    let after_import_list =
        stub_list.and_then(|list| headers_after_import_list(bytes, list, image_start));
    let scanned = stub
        .into_iter()
        .flat_map(|_| scan_for_stored_headers(bytes, image_start));

    from_pack_header
        .into_iter()
        .chain(after_import_list)
        .chain(scanned)
        .find_map(|stored| restore_from(image, stub, &stored, image_start, version.clone()))
}

fn restore_from(
    image: &PeImage<'_>,
    stub: Option<&Stub>,
    stored: &StoredHeaders,
    image_start: usize,
    version: Option<String>,
) -> Option<Unpacked> {
    let model = image.model();
    let mut restored = image.bytes().to_vec();
    write_stored_headers(&mut restored, model.nt_offset, stored, image_start)?;

    let restored_model = parse_memory_image(&restored).ok()?.model;
    let stub_list = stub
        .and_then(|stub| stub.import_loop.as_ref())
        .map(|import_loop| import_loop.list);
    let names = import_names(image, stub, image_start);
    let extra = read_extra_fields(
        &restored,
        &restored_model,
        stored,
        image_start,
        stub_list,
        names,
    )?;

    let mut report = PackerReport::new(NAME, version);
    report.restored.push("headers");

    if read_u32(&restored, restored_model.entry_point_offset).ok()? != 0 {
        report.restored.push("entry point");
    }

    let imports = restore_imports(image.bytes(), names, &extra, image_start, &mut report);

    if !matches!(imports, PackerImports::Intact) {
        clear_directory(&mut restored, &restored_model, BOUND_IMPORT_DIRECTORY);
    }

    let relocations = restore_relocations(&mut restored, &restored_model, &extra, image_start);
    report.record("relocations", relocations);

    let exports = restore_exports(&mut restored, &restored_model, image);
    report.record("exports", exports);

    let resources = restore_resources(&mut restored, &restored_model, image, image_start);
    report.record("resources", resources);

    restore_debug_directory(&mut restored, &restored_model, stored, &mut report);
    parse_memory_image(&restored).ok()?;

    Some(Unpacked {
        image: Some(restored),
        findings: PackerFindings { report, imports },
    })
}

fn import_names(image: &PeImage<'_>, stub: Option<&Stub>, image_start: usize) -> Option<usize> {
    stub.and_then(|stub| stub.import_loop.as_ref())
        .map(|import_loop| import_loop.names)
        .or_else(|| {
            let directory = image.directory(IMPORT_DIRECTORY).ok()??;
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
        report.restored.push("imports");
        return PackerImports::Intact;
    }

    match names.and_then(|names| parse_import_list(bytes, list, names, image_start)) {
        Some(modules) => {
            report.restored.push("imports");
            PackerImports::Listed(modules)
        }
        None => {
            report.unrestored.push(
                "imports (the packer's list was unreadable, so they come from the filled IAT)",
            );
            PackerImports::Unknown
        }
    }
}

fn find_stub(bytes: &[u8], model: &PeModel) -> Option<Stub> {
    let shape = match model.kind() {
        PeKind::Pe32Plus => &X64_STUB,
        PeKind::Pe32 => &X86_STUB,
    };

    let entry = Rva(read_u32(bytes, model.entry_point_offset).ok()?);
    let sections = model.sections();
    let entry_section = sections.iter().find(|section| section.contains_rva(entry));
    let other_code = sections
        .iter()
        .filter(|section| section.is_executable() && !section.contains_rva(entry));
    entry_section
        .into_iter()
        .chain(other_code)
        .find_map(|section| stub_in_section(bytes, section, shape))
}

fn stub_in_section(bytes: &[u8], section: &SectionModel, shape: &StubShape) -> Option<Stub> {
    let start = section.virtual_address().as_usize();
    let end = start
        .saturating_add(section.span() as usize)
        .min(bytes.len());
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
                module: read_c_string(bytes, name_at)?.0,
                first_thunk: u32::try_from(image_start.checked_add(listed.iat_offset)?).ok()?,
                functions: listed.functions,
            })
        })
        .collect()
}

fn read_import_list(bytes: &[u8], start: usize) -> Option<(Vec<ListedModule>, usize)> {
    let mut modules = Vec::new();
    let mut at = start;

    while modules.len() < MAX_IMPORT_MODULES {
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

    while functions.len() < MAX_IMPORT_FUNCTIONS {
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
    version: Option<String>,
    uncompressed_length: usize,
}

fn find_pack_header(bytes: &[u8]) -> Option<PackHeader> {
    let window = bytes.get(..PACK_HEADER_WINDOW.min(bytes.len()))?;
    let magic = window
        .windows(PACK_HEADER_MAGIC.len())
        .position(|candidate| candidate == PACK_HEADER_MAGIC)?;
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
        version,
        uncompressed_length,
    })
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
    let relocation_end = walk_relocations(bytes, list_end)?.1;
    [list_end, relocation_end].into_iter().find_map(|start| {
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

    if model.directory(restored, IMPORT_DIRECTORY).ok()?.is_some() {
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

    let flags = read_u16(restored, model.nt_offset.checked_add(FILE_FLAGS_OFFSET)?).ok()?;
    let mut relocations = None;
    if model
        .directory(restored, BASERELOC_DIRECTORY)
        .ok()?
        .is_some()
        && flags & RELOCS_STRIPPED == 0
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
    let candidates = match model
        .directory(restored, RESOURCE_DIRECTORY)
        .ok()?
        .is_some()
    {
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
        relocations,
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

fn sixteen_bit_relocations(bytes: &[u8], start: usize, flags: u8) -> Option<Vec<(usize, u16)>> {
    let mut lists = Vec::new();

    if flags & LOW_LIST != 0 {
        lists.push(REL_BASED_LOW);
    }

    if flags & HIGH_LIST != 0 {
        lists.push(REL_BASED_HIGH);
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

    Some(entries)
}

fn decode_relocations(
    bytes: &[u8],
    stream: &RelocationStream,
    kind: u16,
    image_start: usize,
) -> Option<Vec<(u32, u16)>> {
    let (positions, end) = walk_relocations(bytes, stream.start)?;
    let mut entries = positions
        .into_iter()
        .map(|offset| (offset, kind))
        .collect::<Vec<_>>();
    if stream.flags & (LOW_LIST | HIGH_LIST) != 0 {
        entries.extend(sixteen_bit_relocations(bytes, end, stream.flags)?);
    }

    entries
        .into_iter()
        .map(|(offset, kind)| Some((u32::try_from(image_start.checked_add(offset)?).ok()?, kind)))
        .collect()
}

fn restore_relocations(
    restored: &mut [u8],
    model: &PeModel,
    extra: &ExtraFields,
    image_start: usize,
) -> Restoration {
    let Ok(Some(directory)) = model.directory(restored, BASERELOC_DIRECTORY) else {
        return Restoration::Absent;
    };

    if read_u16(restored, model.nt_offset.saturating_add(FILE_FLAGS_OFFSET))
        .is_ok_and(|flags| flags & RELOCS_STRIPPED != 0)
    {
        clear_directory(restored, model, BASERELOC_DIRECTORY);
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

    let kind = match model.kind() {
        PeKind::Pe32Plus => REL_BASED_DIR64,
        PeKind::Pe32 => REL_BASED_HIGHLOW,
    };

    let rebuilt = extra
        .relocations
        .as_ref()
        .and_then(|stream| decode_relocations(restored, stream, kind, image_start))
        .and_then(|entries| relocation_blocks(&entries))
        .filter(|blocks| blocks.len() <= size)
        .and_then(|blocks| place(restored, start, &blocks).map(|()| blocks.len()))
        .and_then(|length| set_directory(restored, model, BASERELOC_DIRECTORY, start, length));
    match rebuilt {
        Some(()) => Restoration::Restored,
        None => {
            clear_directory(restored, model, BASERELOC_DIRECTORY);
            Restoration::Failed
        }
    }
}

fn restore_exports(restored: &mut [u8], model: &PeModel, packed: &PeImage<'_>) -> Restoration {
    let Ok(Some(original)) = model.directory(restored, EXPORT_DIRECTORY) else {
        return Restoration::Absent;
    };

    let destination = original.rva().as_usize();

    if exports_intact(restored, destination) {
        return Restoration::Restored;
    }

    let moved = packed
        .directory(EXPORT_DIRECTORY)
        .ok()
        .flatten()
        .and_then(|copy| {
            let size = copy.size() as usize;
            let block =
                moved_export_directory(packed.bytes(), copy.rva().as_usize(), size, destination)?;
            place(restored, destination, &block)?;
            set_directory(restored, model, EXPORT_DIRECTORY, destination, block.len())
        });
    match moved {
        Some(()) => Restoration::Restored,
        None => {
            clear_directory(restored, model, EXPORT_DIRECTORY);
            Restoration::Failed
        }
    }
}

fn restore_resources(
    restored: &mut [u8],
    model: &PeModel,
    packed: &PeImage<'_>,
    image_start: usize,
) -> Restoration {
    let Ok(Some(destination)) = model.directory(restored, RESOURCE_DIRECTORY) else {
        return Restoration::Absent;
    };

    let rva = destination.rva().as_usize();
    let tree = packed_resources(packed, image_start);

    if resources_intact(restored, rva) {
        if let Some(tree) = &tree {
            tree.return_kept_leaves(restored, rva);
        }

        return Restoration::Restored;
    }

    let moved = tree.and_then(|tree| {
        if !tree.fits(restored, rva, destination.size() as usize) {
            return None;
        }

        tree.apply(restored, rva)
    });

    match moved {
        Some(()) => Restoration::Restored,
        None => {
            clear_directory(restored, model, RESOURCE_DIRECTORY);
            Restoration::Failed
        }
    }
}

fn restore_debug_directory(
    restored: &mut [u8],
    model: &PeModel,
    stored: &StoredHeaders,
    report: &mut PackerReport,
) {
    let Ok(Some(directory)) = model.directory(restored, DEBUG_DIRECTORY) else {
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
        report.restored.push("debug directory");
        return;
    }

    let mut kept = entries
        .iter()
        .filter(|entry| !is_erased(entry))
        .copied()
        .collect::<Vec<_>>(); // upx 5.1 and later keep the cet entry
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
            let _ = set_directory(restored, model, DEBUG_DIRECTORY, start, rebuilt.len());
            report.restored.push(match codeview {
                Some(_) => "debug directory (CodeView entry)",
                None => "debug directory",
            });
        }
        _ => clear_directory(restored, model, DEBUG_DIRECTORY),
    }

    if erased > usize::from(codeview.is_some()) {
        report.lost.push("debug entries the packer erased");
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
    let directory = packed.directory(RESOURCE_DIRECTORY).ok()??;
    let start = directory.rva().as_usize();
    let section = packed
        .model()
        .sections()
        .iter()
        .find(|section| section.contains_rva(directory.rva()))?;
    let section_end = section
        .virtual_address()
        .as_usize()
        .saturating_add(section.span() as usize);

    let bytes = packed.bytes();
    let tree = walk_resources(bytes, start)?;
    let leaves = tree
        .data_entries
        .into_iter()
        .map(|entry| {
            let at = start.checked_add(entry)?;
            let rva = read_u32(bytes, at).ok()? as usize;
            let size = read_u32(bytes, at.checked_add(RESOURCE_DATA_SIZE_OFFSET)?).ok()? as usize;
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

    fn return_kept_leaves(&self, restored: &mut [u8], tree_start: usize) {
        let Some(tree) = walk_resources(restored, tree_start) else {
            return;
        };

        let listed = tree
            .data_entries
            .iter()
            .filter_map(|entry| {
                let at = tree_start.checked_add(*entry)?;
                let rva = read_u32(restored, at).ok()? as usize;
                let size = read_u32(restored, at.checked_add(RESOURCE_DATA_SIZE_OFFSET)?).ok()?;
                Some((rva, size as usize))
            })
            .collect::<Vec<_>>();
        for leaf in &self.leaves {
            let Some(original) = leaf.original else {
                continue;
            };

            if original == leaf.rva || !listed.contains(&(original, leaf.size)) {
                continue;
            }

            if let Some(data) = self.bytes.get(leaf.rva..leaf.rva.saturating_add(leaf.size)) {
                let _ = place(restored, original, data);
            }
        }
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
