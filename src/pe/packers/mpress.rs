use super::codecs::{lzma, lzmat};
use super::tables::{
    FIRST_SECTION_RVA, LinkerTree, RESOURCE_DATA_SIZE_OFFSET, RESOURCE_SIZE_ALIGNMENT, Restoration,
    SectionHints, clear_directory, export_functions, fresh_image, iat_span, linker_export_layout,
    linker_resource_layout, place, pogo_parts, pogo_sections, pogo_tls_directory, read_c_string,
    relocation_blocks, relocations_intact, replace_first_section, restore_tls, return_moved_leaves,
    set_directory, split_merged_section, walk_resources,
};
use super::{
    ImportedFunction, ModuleImports, Origin, PackerFindings, PackerImports, PackerReport, Unpacked,
    find_patterns,
};
use crate::pe::image::{read_pointer, read_u16, read_u32, write_u16, write_u32};
use crate::pe::parse::{parse_disk_image, parse_memory_image};
use crate::pe::{
    BASERELOC_DIRECTORY, BOUND_IMPORT_DIRECTORY, DYNAMIC_BASE, EXCEPTION_DIRECTORY,
    EXPORT_DIRECTORY, IAT_DIRECTORY, IMPORT_DIRECTORY, PeImage, PeKind, PeModel, RELOCATION_DIR64,
    RELOCATION_HIGHLOW, RESOURCE_DIRECTORY, RUNTIME_FUNCTION_SIZE, SectionModel,
};

type Decoder = fn(&[u8], usize) -> Option<Vec<u8>>;

const NAME: &str = "MPRESS";
const X86_STUB: &str = "58 05"; // pop eax / add eax, distance to the data block
const X86_DATA_OFFSET: usize = 2;
const X64_STUB: &str = "48 8D 05"; // lea rax, [rip + distance to the data block]
const X64_DATA_OFFSET: usize = 3;
const X64_LEA_END: usize = 7;
const JUMP: u8 = 0xE9;
const JUMP_SIZE: usize = 5;
const RETURN_TRUE: [u8; 3] = [0xB0, 0x01, 0xC3]; // where a dll without an entry point ends
const HINTS_END: u32 = u32::MAX; // names get zeroed after use, these deltas between iat blocks survive
const MAX_IMPORT_MODULES: usize = 4_096;
const MAX_IAT_SLOTS: usize = 65_536;
const MAX_HINT_ENTRY: usize = 512; // a zeroed dll or function name, plus its terminator
const MIN_HINT_ENTRY: usize = 2; // a zeroed name of at least one character
const LOWEST_MODULE: usize = 0x10000;
const ORDINAL_MARKER: u8 = 0x20; // an ordinal entry starts with a byte at most this, a name with a printable one
const MAX_RELOCATIONS: usize = 1 << 20;
const RELOCATION_MORE: u8 = 1; // fixup distances are big endian, seven bits per byte above this flag
const UNWIND_INFO_OFFSET: usize = 8;
const UNWIND_CHAINED: u32 = 1; // points at another runtime function instead of unwind info
const UNWIND_VERSION_MASK: u8 = 0x07; // mpress zeroes the headers of the unwind entries it drops
const EXPORT_ALIGNMENT: usize = 2; // msvc pads its export data to an even size
const PAYLOAD_HEADER: usize = 6; // size in pages, then the packed size
const PAGE_SHIFT: u32 = 12;
const LITERAL_POSITION_MASK: u8 = 0x0F;
const POSITION_SHIFT: u8 = 4;
const FILTER_TAIL: usize = 0x1000; // the stub leaves the last page unfiltered
const CALL: u8 = 0xE8;
const INDIRECT: u8 = 0xFF;
const RIP_INDIRECT_MASK: u8 = 0xFD; // call or jmp [rip + x]
const RIP_INDIRECT: u8 = 0x15;
const LOAD_ADDRESS: u8 = 0x8D;
const RIP_ADDRESS_MASK: u8 = 0xC7; // lea reg, [rip + x]
const RIP_ADDRESS: u8 = 0x05;
const PAGE: usize = 0x1000;

struct Stub {
    stub_start: usize,
    data: Fields,
    fixer: usize,
}

struct Fields {
    relocation_size: usize,
    relocation_rva: usize,
}

struct Finished {
    entry: Option<usize>,
    hints: usize,
}

struct IatBlock {
    start: usize,
    slots: usize,
    by_ordinal: bool,
    listed: Option<(String, Vec<ImportedFunction>)>,
}

pub(super) fn unpack(image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
    let bytes = image.bytes();
    let model = image.model();
    let stub = find_stub(bytes, model)?;
    let Some(finished) = follow_fixer(bytes, &stub, model.kind()) else {
        let reason = "image (the stub had not finished unpacking)";
        return Some(Unpacked::detected_only(NAME, None, reason));
    };

    let reason = "image (its tables could not be read)";
    restore(image, &stub, &finished, origin)
        .or_else(|| Some(Unpacked::detected_only(NAME, None, reason)))
}

fn find_stub(bytes: &[u8], model: &PeModel) -> Option<Stub> {
    let first_section = model.sections().first()?.virtual_address().as_usize();
    model
        .sections()
        .iter()
        .skip(1)
        .rev()
        .filter(|section| section.is_executable())
        .find_map(|section| stub_in_section(bytes, section, model.kind(), first_section))
}

fn stub_in_section(
    bytes: &[u8],
    section: &SectionModel,
    kind: PeKind,
    first_section: usize,
) -> Option<Stub> {
    let start = section.virtual_address().as_usize();
    let end = start
        .saturating_add(section.span() as usize)
        .min(bytes.len());
    let pattern = match kind {
        PeKind::Pe32 => X86_STUB,
        PeKind::Pe32Plus => X64_STUB,
    };

    find_patterns(bytes.get(start..end)?, pattern).find_map(|found| {
        let at = start.checked_add(found)?;
        let data = match kind {
            PeKind::Pe32 => {
                at.checked_add(read_u32(bytes, at.checked_add(X86_DATA_OFFSET)?).ok()? as usize)?
            }
            PeKind::Pe32Plus => relative(
                bytes,
                at.checked_add(X64_DATA_OFFSET)?,
                at.checked_add(X64_LEA_END)?,
            )?,
        };

        data_block(bytes, data, kind, first_section, start)
    })
}

fn data_block(
    bytes: &[u8],
    data: usize,
    kind: PeKind,
    first_section: usize,
    stub_start: usize,
) -> Option<Stub> {
    let jump = data.checked_sub(JUMP_SIZE)?;
    (*bytes.get(jump)? == JUMP).then_some(())?;

    let field = |offset: usize| -> Option<usize> {
        let offset = offset.checked_add(kind.pointer_width() - 4)?; // x64 fields follow a qword
        Some(read_u32(bytes, data.checked_add(offset)?).ok()? as usize)
    };

    (relative(bytes, data, data)? == first_section).then_some(())?;

    let fixer = relative(bytes, jump.checked_add(1)?, data)?;
    (fixer > first_section && fixer < stub_start).then_some(())?;

    let relocation_size = field(4)?;
    let relocation_rva = match relocation_size {
        0 => 0, // exes end the block here
        _ => field(12)?,
    };

    Some(Stub {
        stub_start,
        data: Fields {
            relocation_size,
            relocation_rva,
        },
        fixer,
    })
}

fn relative(bytes: &[u8], operand: usize, next: usize) -> Option<usize> {
    let displacement = read_u32(bytes, operand).ok()? as i32;
    next.checked_add_signed(displacement as isize)
}

fn follow_fixer(bytes: &[u8], stub: &Stub, kind: PeKind) -> Option<Finished> {
    let target = |at: usize| -> Option<usize> {
        (*bytes.get(at)? == JUMP).then_some(())?;
        relative(bytes, at.checked_add(1)?, at.checked_add(JUMP_SIZE)?)
    };

    let last = target(stub.fixer)?;
    let entry = match bytes.get(last..last.checked_add(RETURN_TRUE.len())?)? {
        ending if ending == RETURN_TRUE => None,
        _ => Some(target(last)?),
    };

    let hints_field = last.checked_add(JUMP_SIZE)?;
    let hints = hints_field.checked_add_signed(signed(bytes, hints_field, kind)?)?;
    let in_image = |rva: usize| (FIRST_SECTION_RVA..stub.stub_start).contains(&rva);

    (entry.is_none_or(in_image) && in_image(hints)).then_some(Finished { entry, hints })
}

fn signed(bytes: &[u8], at: usize, kind: PeKind) -> Option<isize> {
    let value = read_pointer(bytes, at, kind).ok()?;
    Some(match kind {
        PeKind::Pe32 => value as u32 as i32 as isize,
        PeKind::Pe32Plus => value as isize,
    })
}

fn restore(
    image: &PeImage<'_>,
    stub: &Stub,
    finished: &Finished,
    origin: &Origin<'_>,
) -> Option<Unpacked> {
    let model = image.model();
    let base = origin.base;
    let kind = model.kind();
    let mut restored = image.bytes().to_vec();
    let mut report = PackerReport::new(NAME, None);

    let entry = finished.entry.unwrap_or_default();
    write_u32(
        &mut restored,
        model.entry_point_offset,
        u32::try_from(entry).ok()?,
    )
    .ok()?;
    if finished.entry.is_some() {
        report.restored.push("entry point");
    }

    let scan = |listing: &[u8]| {
        iat_blocks(
            &restored,
            listing,
            finished.hints,
            kind,
            base,
            stub.stub_start,
        )
    };

    let file = origin.read_file();
    let originals = original_images(file.as_deref(), restored.len(), kind);
    let file_base = originals.as_ref().map(|(file_base, _)| *file_base);
    let from_file = originals.and_then(|(_, images)| {
        images
            .filter(|image| matches_memory(image, &restored))
            .find_map(|image| {
                scan(&image)
                    .filter(|blocks| blocks.iter().all(|block| block.listed.is_some()))
                    .map(|blocks| (blocks, image))
            })
    }); // the file still holds the names the stub zeroes once it has run

    let (blocks, original) = match from_file {
        Some((blocks, image)) => (blocks, Some(image)),
        None => (scan(&restored)?, None),
    };
    let (iat, iat_size) = iat_span(
        blocks.iter().map(|block| (block.start, block.slots)),
        kind.pointer_width(),
    )?;
    clear_directory(&mut restored, model, IMPORT_DIRECTORY);
    set_directory(&mut restored, model, IAT_DIRECTORY, iat, iat_size)?;
    report.restored.push("imports");

    let resources = restore_resources(&mut restored, model, stub.stub_start);
    report.record("resource layout", resources);

    let relocations = restore_relocations(&mut restored, model, stub);
    let relocation_section =
        matches!(relocations, Restoration::Restored).then_some(stub.data.relocation_rva);
    report.record("relocations", relocations);

    let forwarders = restore_forwarders(&mut restored, model, stub.stub_start);
    report.record("export forwarders", forwarders);

    let pogo = pogo_parts(&restored, model, stub.stub_start);
    let tls = restore_tls(
        &mut restored,
        model,
        base,
        stub.stub_start,
        pogo.as_deref().and_then(pogo_tls_directory),
    );
    report.record("TLS", tls);

    if unwind_info_erased(&restored, model) {
        report.lost.push("unwind info");
    }

    let linker_pieces = pogo
        .as_deref()
        .and_then(|parts| pogo_sections(parts, model, stub.stub_start, finished.entry));
    match linker_pieces {
        Some(pieces) if replace_first_section(&mut restored, model, &pieces).is_some() => {
            report.restored.push("section table");
        }
        _ => {
            let hints = SectionHints {
                code: finished.entry,
                code_end: None,
                constants: None,
                relocations: relocation_section,
                resources: None,
            };
            if split_merged_section(&mut restored, model, &hints, None, None).is_some() {
                report.restored.push("code and data sections");
            }
            report.lost.push("section table");
        }
    }

    clear_directory(&mut restored, model, BOUND_IMPORT_DIRECTORY);
    parse_memory_image(&restored).ok()?;

    let modules = blocks
        .iter()
        .map(|block| {
            let function = match block.by_ordinal {
                true => ImportedFunction::OrdinalFromAddress,
                false => ImportedFunction::NameFromAddress,
            };

            let (module, functions) = block.listed.clone().unwrap_or_else(|| {
                (String::new(), vec![function; block.slots]) // the planner names erased ones from the slots
            });

            Some(ModuleImports {
                module,
                first_thunk: u32::try_from(block.start).ok()?,
                functions,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    let imports = PackerImports::Listed(modules);

    let fresh = original.zip(file_base).and_then(|(original, file_base)| {
        fresh_image(
            image.bytes(),
            &restored,
            &original,
            file_base,
            base,
            stub.stub_start,
            &[],
        )
    });

    Some(Unpacked {
        image: Some(restored),
        findings: PackerFindings { report, imports },
        fresh,
    })
}

fn matches_memory(decoded: &[u8], memory: &[u8]) -> bool {
    let same = decoded
        .iter()
        .zip(memory)
        .filter(|(left, right)| left == right)
        .count();
    same.saturating_mul(4) >= decoded.len().saturating_mul(3) // pointers and runtime data differ, real decodes still match 96% or more
}

fn original_images(
    file: Option<&[u8]>,
    image_size: usize,
    kind: PeKind,
) -> Option<(usize, impl Iterator<Item = Vec<u8>>)> {
    let file = file?;
    let disk = parse_disk_image(file).ok()?;
    let file_base = read_pointer(file, disk.model().image_base_offset, kind).ok()?;
    let section = disk.model().sections().first()?;
    let first = section.virtual_address().as_usize();
    let raw = section.raw_pointer as usize;
    let payload = file.get(raw..raw.checked_add(section.raw_size as usize)?)?;

    let size = usize::from(read_u16(payload, 0).ok()?) << PAGE_SHIFT;
    let packed_size = read_u32(payload, 2).ok()? as usize;
    let stream_end = PAYLOAD_HEADER.checked_add(packed_size)?.min(payload.len()); // lzmat counts a few bytes past the section, the decoders pad short reads
    let stream = payload.get(PAYLOAD_HEADER..stream_end)?;
    (first.checked_add(size)? <= image_size).then_some(())?;

    let decoders: [Decoder; 2] = [decompress_lzma, lzmat::decompress]; // only the stub says which one packed it

    let images = decoders.into_iter().filter_map(move |decode| {
        let mut image = vec![0; first];
        image.extend(decode(stream, size)?);
        unfilter(image.get_mut(first..)?, kind);
        Some(image)
    });
    Some((file_base, images))
}

fn decompress_lzma(stream: &[u8], size: usize) -> Option<Vec<u8>> {
    let [packed, literal_context, rest @ ..] = stream else {
        return None;
    };

    let properties = lzma::Properties {
        literal_context: *literal_context,
        literal_position: packed & LITERAL_POSITION_MASK,
        position: packed >> POSITION_SHIFT,
    };
    lzma::decompress(rest, &properties, size)
}

fn unfilter(bytes: &mut [u8], kind: PeKind) {
    let x64 = matches!(kind, PeKind::Pe32Plus);
    let limit = bytes.len().saturating_sub(FILTER_TAIL);
    let mut at = 0;

    while at < limit {
        let modrm = bytes[at + 1];
        let operand = match bytes[at] {
            CALL | JUMP => at + 1,
            INDIRECT if x64 && modrm & RIP_INDIRECT_MASK == RIP_INDIRECT => at + 2,
            LOAD_ADDRESS if x64 && modrm & RIP_ADDRESS_MASK == RIP_ADDRESS => at + 2,
            _ => {
                at += 1;
                continue;
            }
        };
        at = operand + 4;

        let Ok(value) = read_u32(bytes, operand) else {
            break;
        };
        let value = i64::from(value as i32);
        let (position, limit) = (operand as i64, limit as i64);

        let relative = match value {
            0.. if value < limit => value - position,
            ..0 if value + position >= 0 => value + limit,
            _ => continue,
        };
        if write_u32(bytes, operand, relative as i32 as u32).is_err() {
            break;
        }
    }
}

fn iat_blocks(
    memory: &[u8],
    listing: &[u8],
    hints: usize,
    kind: PeKind,
    base: usize,
    end: usize,
) -> Option<Vec<IatBlock>> {
    let width = kind.pointer_width();
    let image = base..base.saturating_add(end);
    let filled = |at: usize| {
        read_pointer(memory, at, kind)
            .is_ok_and(|value| value >= LOWEST_MODULE && !image.contains(&value))
    };

    let named = |at: usize| {
        read_c_string(listing, at)
            .is_some_and(|(name, _)| name.bytes().all(|byte| byte.is_ascii_graphic()))
    };

    let kept_names = named(hints.checked_add(width)?);
    let block_at = |cursor: usize, delta_at: usize, blocks: &[IatBlock]| -> Option<IatBlock> {
        let name = delta_at.checked_add(width)?;
        let start = cursor.checked_add_signed(signed(listing, delta_at, kind)?)?;
        let erased = listing.get(name..name.checked_add(MIN_HINT_ENTRY)?)? == [0; MIN_HINT_ENTRY];
        let fits = (if kept_names { named(name) } else { erased })
            && (FIRST_SECTION_RVA..end).contains(&start)
            && start.is_multiple_of(width)
            && filled(start)
            && !filled(start.checked_sub(width)?);
        fits.then_some(())?;

        let slots = (0..MAX_IAT_SLOTS).find(|slot| !filled(start + slot * width))?;
        let stop = start.checked_add(slots.checked_mul(width)?)?;
        let overlaps = blocks
            .iter()
            .any(|block| start < block.start + (block.slots + 1) * width && block.start <= stop);
        (!overlaps).then_some(IatBlock {
            start,
            slots,
            by_ordinal: false,
            listed: None,
        })
    };

    let mut blocks = Vec::new();
    let mut cursor = hints;
    let mut delta_at = hints;

    for _ in 0..MAX_IMPORT_MODULES {
        if read_u32(listing, delta_at).ok()? == HINTS_END {
            return (!blocks.is_empty()).then_some(blocks);
        }

        let mut block = block_at(cursor, delta_at, &blocks)?;
        cursor = block.start.checked_add(block.slots.checked_mul(width)?)?;

        if let Some((module, functions, next)) = kept_names
            .then(|| listed_hints(listing, delta_at.checked_add(width)?))
            .flatten()
        {
            (functions.len() == block.slots).then_some(())?;
            block.listed = Some((module, functions));
            blocks.push(block);
            delta_at = next;
            continue;
        }

        let first_candidate = delta_at
            .checked_add(width)?
            .checked_add(MIN_HINT_ENTRY.checked_mul(block.slots.checked_add(1)?)?)?
            .checked_add(1)?;
        let last_candidate = first_candidate
            .checked_add(MAX_HINT_ENTRY.checked_mul(block.slots.checked_add(1)?)?)?;
        let next = (first_candidate..last_candidate).find(|at| {
            read_u32(listing, *at).is_ok_and(|value| value == HINTS_END)
                || block_at(cursor, *at, &blocks).is_some()
        })?;

        let markers = listing
            .get(delta_at.checked_add(width)?..next)?
            .iter()
            .filter(|byte| (1..=ORDINAL_MARKER).contains(*byte))
            .count();
        block.by_ordinal = markers == block.slots;
        blocks.push(block);
        delta_at = next;
    }

    None
}

fn listed_hints(bytes: &[u8], at: usize) -> Option<(String, Vec<ImportedFunction>, usize)> {
    let (module, mut at) = read_c_string(bytes, at)?;
    let mut functions = Vec::new();
    for _ in 0..MAX_IAT_SLOTS {
        match *bytes.get(at)? {
            0 => return Some((module, functions, at.checked_add(1)?)),
            1..=ORDINAL_MARKER => {
                let ordinal = read_u16(bytes, at.checked_add(1)?).ok()?;
                functions.push(ImportedFunction::Ordinal(ordinal));
                at = at.checked_add(3)?;
            }
            _ => {
                let (name, next) = read_c_string(bytes, at)?;
                functions.push(ImportedFunction::Name(name));
                at = next;
            }
        }
    }

    None
}

fn restore_resources(restored: &mut [u8], model: &PeModel, end: usize) -> Restoration {
    let Ok(Some(directory)) = model.directory(restored, RESOURCE_DIRECTORY) else {
        return Restoration::Absent;
    };

    let packed_root = directory.rva().as_usize();
    if packed_root < end {
        return Restoration::Absent;
    }

    let Some(tree) = linker_resource_layout(restored, packed_root) else {
        return Restoration::Failed;
    };
    let Some(start) = original_tree_start(restored, &tree, end) else {
        return Restoration::Lost; // every leaf moved, so nothing marks where the tree sat
    };

    let placed = place(restored, start, &tree.bytes)
        .and_then(|()| set_directory(restored, model, RESOURCE_DIRECTORY, start, tree.bytes.len()));
    if placed.is_none() {
        return Restoration::Failed;
    }

    if matches!(
        return_moved_leaves(restored, start, start..end, end),
        Restoration::Failed
    ) {
        return Restoration::Failed;
    }

    let size = resource_extent(restored, start, end)
        .and_then(|extent| set_directory(restored, model, RESOURCE_DIRECTORY, start, extent));
    match size {
        Some(()) => Restoration::Restored,
        None => Restoration::Failed,
    }
}

fn original_tree_start(restored: &[u8], tree: &LinkerTree, end: usize) -> Option<usize> {
    let lowest = tree
        .data_entries
        .iter()
        .filter_map(|entry| read_u32(&tree.bytes, *entry).ok())
        .map(|rva| rva as usize)
        .filter(|rva| *rva < end)
        .min()?; // msvc puts the tree first in the section, before every leaf

    let mut start = lowest - lowest % PAGE;
    loop {
        restored
            .get(start..lowest)?
            .iter()
            .all(|byte| *byte == 0)
            .then_some(())?;
        if start + tree.bytes.len() <= lowest {
            return Some(start);
        }

        start = start.checked_sub(PAGE)?;
    }
}

fn resource_extent(restored: &[u8], start: usize, end: usize) -> Option<usize> {
    let tree = walk_resources(restored, start)?;
    let last = tree
        .data_entries
        .iter()
        .filter_map(|entry| {
            let at = start.checked_add(*entry)?;
            let rva = read_u32(restored, at).ok()? as usize;
            let size =
                read_u32(restored, at.checked_add(RESOURCE_DATA_SIZE_OFFSET)?).ok()? as usize;
            (start..end)
                .contains(&rva)
                .then(|| rva.checked_add(size))
                .flatten()
        })
        .max()?;

    Some((last - start).next_multiple_of(RESOURCE_SIZE_ALIGNMENT))
}

fn restore_relocations(restored: &mut [u8], model: &PeModel, stub: &Stub) -> Restoration {
    let Fields {
        relocation_size: size,
        relocation_rva: start,
    } = stub.data;

    if size == 0 {
        clear_directory(restored, model, BASERELOC_DIRECTORY);
        return match model.is_dll {
            true => Restoration::Absent,
            false => Restoration::Lost, // mpress strips them from every exe it packs
        };
    }

    let kind = match model.kind() {
        PeKind::Pe32 => RELOCATION_HIGHLOW,
        PeKind::Pe32Plus => RELOCATION_DIR64,
    };

    let in_place =
        start.saturating_add(size) <= stub.stub_start && relocations_intact(restored, start, size); // releases up to 2.05 keep the original blocks
    let table = match in_place {
        true => restored.get(start..start + size).map(<[u8]>::to_vec),
        false => decode_relocations(restored, start, size, stub.stub_start).and_then(|positions| {
            let entries = positions
                .into_iter()
                .map(|rva| Some((u32::try_from(rva).ok()?, kind)))
                .collect::<Option<Vec<_>>>()?;
            relocation_blocks(&entries)
        }),
    }
    .filter(|table| {
        let end = start.saturating_add(table.len());
        end <= stub.stub_start
            && restored
                .get(start.saturating_add(size).min(end)..end)
                .is_some_and(|free| free.iter().all(|byte| *byte == 0))
    });

    let written = table.and_then(|table| {
        restored
            .get_mut(start..start.checked_add(table.len())?)?
            .copy_from_slice(&table);
        set_directory(restored, model, BASERELOC_DIRECTORY, start, table.len())?;

        let flags = read_u16(restored, model.dll_characteristics_offset).ok()?;
        write_u16(
            restored,
            model.dll_characteristics_offset,
            flags | DYNAMIC_BASE,
        )
        .ok()
    });

    match written {
        Some(()) => Restoration::Restored,
        None => {
            clear_directory(restored, model, BASERELOC_DIRECTORY);
            Restoration::Failed
        }
    }
}

fn decode_relocations(bytes: &[u8], start: usize, size: usize, end: usize) -> Option<Vec<usize>> {
    let stream = bytes.get(start..start.checked_add(size)?)?;
    let mut positions = Vec::new();
    let mut current = 0usize;
    let mut delta = 0usize;

    for byte in stream {
        delta = delta.checked_mul(1 << 7)? | usize::from(byte >> 1);

        if byte & RELOCATION_MORE != 0 {
            continue;
        }

        if delta == 0 {
            break;
        }

        current = current.checked_add(delta)?;

        if current >= end || positions.len() >= MAX_RELOCATIONS {
            return None;
        }

        positions.push(current);
        delta = 0;
    }

    (!positions.is_empty()).then_some(positions)
}

fn unwind_info_erased(bytes: &[u8], model: &PeModel) -> bool {
    if model.kind() != PeKind::Pe32Plus {
        return false;
    }

    let Ok(Some(table)) = model.directory(bytes, EXCEPTION_DIRECTORY) else {
        return false;
    };

    let start = table.rva().as_usize();
    let count = table.size() as usize / RUNTIME_FUNCTION_SIZE;

    (0..count).any(|index| {
        let entry = start + index * RUNTIME_FUNCTION_SIZE + UNWIND_INFO_OFFSET;
        read_u32(bytes, entry).is_ok_and(|unwind| {
            unwind & UNWIND_CHAINED == 0
                && bytes
                    .get(unwind as usize)
                    .is_some_and(|header| header & UNWIND_VERSION_MASK == 0)
        })
    })
}

fn restore_forwarders(restored: &mut [u8], model: &PeModel, end: usize) -> Restoration {
    let Ok(Some(copy)) = model.directory(restored, EXPORT_DIRECTORY) else {
        return Restoration::Absent;
    };

    let copy = copy.rva().as_usize();
    let forwarders = export_functions(restored, copy)
        .unwrap_or_default()
        .into_iter()
        .filter(|rva| *rva < end && is_forwarder(restored, *rva))
        .filter_map(|rva| Some((rva, read_c_string(restored, rva)?.0)))
        .collect::<Vec<_>>();
    if forwarders.is_empty() {
        return Restoration::Absent;
    }

    let rebuilt =
        linker_export_layout(restored, copy, &forwarders, None).and_then(|(start, block)| {
            place(restored, start, &block)?;

            let size = block.len().checked_next_multiple_of(EXPORT_ALIGNMENT)?;
            set_directory(restored, model, EXPORT_DIRECTORY, start, size)
        });

    match rebuilt {
        Some(()) => Restoration::Restored,
        None => Restoration::Failed,
    }
}

fn is_forwarder(bytes: &[u8], at: usize) -> bool {
    let preceded_by_zero = at.checked_sub(1).and_then(|before| bytes.get(before)) == Some(&0);
    let module_name = |module: &str| {
        module
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    };

    preceded_by_zero
        && read_c_string(bytes, at).is_some_and(|(text, _)| {
            text.split_once('.').is_some_and(|(module, function)| {
                !module.is_empty()
                    && !function.is_empty()
                    && module_name(module)
                    && function.bytes().all(|byte| byte.is_ascii_graphic())
            })
        })
}
