use super::tables::{
    FIRST_SECTION_RVA, Restoration, SECTION_CHARACTERISTICS_OFFSET, SECTION_COUNT_OFFSET,
    SECTION_RVA_OFFSET, clear_directory, export_functions, find_tls_by_template, iat_span,
    linker_export_layout, place, read_c_string, relocation_blocks, relocations_intact,
    set_directory, set_tls_directory,
};
use super::{
    ImportedFunction, ModuleImports, Origin, PackerFindings, PackerImports, PackerReport, Unpacked,
    find_patterns,
};
use crate::pe::image::{read_pointer, read_u16, read_u32, write_u16, write_u32};
use crate::pe::parse::parse_memory_image;
use crate::pe::{
    BASERELOC_DIRECTORY, BOUND_IMPORT_DIRECTORY, DYNAMIC_BASE, EXCEPTION_DIRECTORY,
    EXPORT_DIRECTORY, IAT_DIRECTORY, IMPORT_DIRECTORY, PeImage, PeKind, PeModel, RELOCATION_DIR64,
    RELOCATION_HIGHLOW, RUNTIME_FUNCTION_SIZE, SECTION_HEADER_SIZE, SectionModel, TLS_DIRECTORY,
};

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
const SECTION_VIRTUAL_SIZE_OFFSET: usize = 8;
const SECTION_RAW_SIZE_OFFSET: usize = 16;
const SECTION_RAW_POINTER_OFFSET: usize = 20;
const CODE_SECTION: u32 = 0x6000_0020; // read, execute, code
const DATA_SECTION: u32 = 0xC000_0040; // read, write, initialized data
const RELOCATION_SECTION: u32 = 0x4200_0040; // read, discardable, initialized data
const EXPORT_ALIGNMENT: usize = 2; // msvc pads its export data to an even size

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
    restore(image, &stub, &finished, origin.base)
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

fn restore(image: &PeImage<'_>, stub: &Stub, finished: &Finished, base: usize) -> Option<Unpacked> {
    let model = image.model();
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

    let blocks = iat_blocks(&restored, finished.hints, kind, base, stub.stub_start)?;
    let (iat, iat_size) = iat_span(
        blocks.iter().map(|block| (block.start, block.slots)),
        kind.pointer_width(),
    )?;
    clear_directory(&mut restored, model, IMPORT_DIRECTORY);
    set_directory(&mut restored, model, IAT_DIRECTORY, iat, iat_size)?;
    report.restored.push("imports");

    let relocations = restore_relocations(&mut restored, model, stub);
    let relocation_section =
        matches!(relocations, Restoration::Restored).then_some(stub.data.relocation_rva);
    report.record("relocations", relocations);

    let forwarders = restore_forwarders(&mut restored, model, stub.stub_start);
    report.record("export forwarders", forwarders);

    let tls = restore_tls(&mut restored, model, base, stub.stub_start);
    report.record("TLS", tls);

    if unwind_info_erased(&restored, model) {
        report.lost.push("unwind info");
    }

    if split_sections(&mut restored, model, finished.entry, relocation_section).is_some() {
        report.restored.push("code and data sections");
    }
    report.lost.push("section table");

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

    Some(Unpacked {
        image: Some(restored),
        findings: PackerFindings { report, imports },
    })
}

fn iat_blocks(
    bytes: &[u8],
    hints: usize,
    kind: PeKind,
    base: usize,
    end: usize,
) -> Option<Vec<IatBlock>> {
    let width = kind.pointer_width();
    let image = base..base.saturating_add(end);
    let filled = |at: usize| {
        read_pointer(bytes, at, kind)
            .is_ok_and(|value| value >= LOWEST_MODULE && !image.contains(&value))
    };

    let named = |at: usize| {
        read_c_string(bytes, at)
            .is_some_and(|(name, _)| name.bytes().all(|byte| byte.is_ascii_graphic()))
    };

    let kept_names = named(hints.checked_add(width)?);
    let block_at = |cursor: usize, delta_at: usize, blocks: &[IatBlock]| -> Option<IatBlock> {
        let name = delta_at.checked_add(width)?;
        let start = cursor.checked_add_signed(signed(bytes, delta_at, kind)?)?;
        let erased = bytes.get(name..name.checked_add(MIN_HINT_ENTRY)?)? == [0; MIN_HINT_ENTRY];
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
        if read_u32(bytes, delta_at).ok()? == HINTS_END {
            return (!blocks.is_empty()).then_some(blocks);
        }

        let mut block = block_at(cursor, delta_at, &blocks)?;
        cursor = block.start.checked_add(block.slots.checked_mul(width)?)?;

        if let Some((module, functions, next)) = kept_names
            .then(|| listed_hints(bytes, delta_at.checked_add(width)?))
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
            read_u32(bytes, *at).is_ok_and(|value| value == HINTS_END)
                || block_at(cursor, *at, &blocks).is_some()
        })?;

        let markers = bytes
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

fn split_sections(
    restored: &mut [u8],
    model: &PeModel,
    entry: Option<usize>,
    relocations: Option<usize>,
) -> Option<()> {
    let packed = model.sections().first()?;
    let start = packed.virtual_address().as_usize();
    let end = start.checked_add(packed.span() as usize)?;
    let alignment = model.section_alignment as usize;
    let code_start = read_u32(restored, model.base_of_code_offset).ok()? as usize; // mpress keeps these
    let code_size = read_u32(restored, model.size_of_code_offset).ok()? as usize;
    let code_end = code_start
        .checked_add(code_size)?
        .checked_next_multiple_of(alignment)?;
    let fits = code_start == start
        && code_end > start
        && code_end < end
        && entry.is_none_or(|entry| (start..code_end).contains(&entry));
    fits.then_some(())?;

    let mut pieces = vec![(*b".text\0\0\0", start, code_end, CODE_SECTION)];
    match relocations
        .filter(|rva| rva.is_multiple_of(alignment) && (code_end + 1..end).contains(rva))
    {
        Some(relocations) => {
            pieces.push((*b".data\0\0\0", code_end, relocations, DATA_SECTION));
            pieces.push((*b".reloc\0\0", relocations, end, RELOCATION_SECTION));
        }
        None => pieces.push((*b".data\0\0\0", code_end, end, DATA_SECTION)),
    }

    let mut table = Vec::new();
    for (name, piece_start, piece_end, characteristics) in pieces {
        let mut header = [0u8; SECTION_HEADER_SIZE];
        header[..name.len()].copy_from_slice(&name);

        let size = u32::try_from(piece_end.checked_sub(piece_start)?).ok()?;
        let rva = u32::try_from(piece_start).ok()?;
        for (offset, value) in [
            (SECTION_VIRTUAL_SIZE_OFFSET, size),
            (SECTION_RVA_OFFSET, rva),
            (SECTION_RAW_SIZE_OFFSET, size),
            (SECTION_RAW_POINTER_OFFSET, rva),
            (SECTION_CHARACTERISTICS_OFFSET, characteristics),
        ] {
            write_u32(&mut header, offset, value).ok()?;
        }

        table.extend_from_slice(&header);
    }

    let first = packed.header_offset;
    let rest = model
        .sections()
        .len()
        .checked_sub(1)?
        .checked_mul(SECTION_HEADER_SIZE)?;
    let old_end = first.checked_add(SECTION_HEADER_SIZE)?.checked_add(rest)?;
    let new_end = first.checked_add(table.len())?.checked_add(rest)?;
    let headers_end = read_u32(restored, model.size_of_headers_offset).ok()? as usize;
    let grown = restored.get(headers_end.max(old_end)..new_end.max(headers_end));

    (new_end <= start && grown.is_some_and(|tail| tail.iter().all(|byte| *byte == 0)))
        .then_some(())?;

    if new_end > headers_end {
        let headers_end = new_end.checked_next_multiple_of(model.file_alignment as usize)?;
        write_u32(
            restored,
            model.size_of_headers_offset,
            u32::try_from(headers_end).ok()?,
        )
        .ok()?;
    }

    let others = restored
        .get(first.checked_add(SECTION_HEADER_SIZE)?..old_end)?
        .to_vec();
    table.extend_from_slice(&others);
    restored.get_mut(first..new_end)?.copy_from_slice(&table);

    let count = u16::try_from(table.len() / SECTION_HEADER_SIZE).ok()?;
    write_u16(
        restored,
        model.nt_offset.checked_add(SECTION_COUNT_OFFSET)?,
        count,
    )
    .ok()
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

    let rebuilt = linker_export_layout(restored, copy, &forwarders).and_then(|(start, block)| {
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

fn restore_tls(restored: &mut [u8], model: &PeModel, base: usize, end: usize) -> Restoration {
    let Ok(Some(copy)) = model.directory(restored, TLS_DIRECTORY) else {
        return Restoration::Absent;
    };

    let original = find_tls_by_template(restored, copy.rva().as_usize(), model.kind(), base, end);

    match original.and_then(|rva| set_tls_directory(restored, model, rva)) {
        Some(()) => Restoration::Restored,
        None => Restoration::Failed,
    }
}
