use std::ops::Range;

use super::{NAMED_BY_CONTENTS, Packer, SPLIT_BY_HEADER, UNPROVEN_FLAGS, resolved_import};
use crate::pe::UNWIND_INFO_OFFSET;
use crate::pe::bytes::{read_pointer, read_u16, read_u32, write_u16, write_u32};
use crate::pe::parse::{parse_disk_image, parse_memory_image};
use crate::pe::{
    BASERELOC_DIRECTORY, BOUND_IMPORT_DIRECTORY, DYNAMIC_BASE, EXCEPTION_DIRECTORY,
    EXPORT_DIRECTORY, IAT_DIRECTORY, IMPORT_DIRECTORY, MAX_IMPORT_DESCRIPTORS, MAX_IMPORTS,
    MAX_RELOCATIONS, PAGE_SHIFT, PAGE_SIZE, PeImage, PeKind, PeModel, RESOURCE_DIRECTORY,
    RUNTIME_FUNCTION_SIZE, SectionModel, UNWIND_CHAINED, UNWIND_VERSION_MASK,
};
use crate::unpack::codecs::{DecodeError, Decoded, lzma, lzmat};
use crate::unpack::tables::{
    LinkerTree, PlannedSection, RESOURCE_SIZE_ALIGNMENT, Restoration, SectionHints, SectionKind,
    clear_header_slack, export_forwarders, iat_span, linker_export_layout, linker_resource_layout,
    place, pogo_parts, pogo_sections, pogo_tls_directory, read_c_string, recover_directories,
    relocation_blocks, relocations_intact, replace_first_section, resource_leaf, restore_tls,
    restored_or_cleared, return_moved_leaves, split_merged_section, walk_resources,
};
use crate::unpack::x86::branches::{REL32_LEN, relative};
use crate::unpack::x86::opcodes::{CALL_MODRM, CALL_REL32, GROUP_FF, JUMP_REL32, LEA};
use crate::unpack::x86::opcodes::{MODRM_DISP32, MODRM_DISP32_MASK, MOV_REG_IMM32};
use crate::unpack::{
    ImportedFunction, InitialData, ModuleImports, Origin, PACKER_HEADER_BYTES, PackerId,
    PackerImports, PackerReport, Part, Refusal, Step, Unpacked, file_base, find_patterns, hex,
    need, with_initial_data,
};

type Decoder = fn(&[u8], usize) -> Decoded;

const NAME: PackerId = PackerId::Mpress;
const X86_STUB: &str = hex("58 05"); // pop eax / add eax, distance
const X86_DATA_OFFSET: usize = 2;
const X64_STUB: &str = hex("48 8D 05"); // lea rax, [rip + distance]
const X64_DATA_OFFSET: usize = 3;
const X64_LEA_END: usize = 7;
const DATA_RELOCATION_SIZE: usize = 4;
const DATA_RELOCATION_RVA: usize = 12;
const MAX_EPILOGUE: usize = 32; // pops before jmp
const RETURN_TRUE: [u8; 3] = [0xB0, 0x01, 0xC3]; // mov al,1 / ret
const HINTS_END: u32 = u32::MAX; // ends delta list
const MAX_HINT_ENTRY: usize = 512; // longest zeroed name
const MIN_HINT_ENTRY: usize = 2;
const ORDINAL_MARKER: u8 = 0x20; // <= 0x20: ordinal record
const RELOCATION_MORE: u8 = 1; // 7 bit be varint, low bit continues
const EXPORT_ALIGNMENT: usize = 2; // msvc pads exports to even
const PAYLOAD_HEADER: usize = 6; // size in pages, then the packed size
const LITERAL_POSITION_MASK: u8 = 0x0F;
const POSITION_SHIFT: u8 = 4;
const FILTER_TAIL: usize = 0x1000; // last page stays unfiltered
const RIP_INDIRECT_MASK: u8 = 0xFD; // modrm 15 or 17 only, FF 25 is left alone

struct Stub {
    first_section: usize,
    stub_start: usize,
    relocation_size: usize,
    relocation_rva: usize,
    fixer: usize,
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

fn unpack(image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
    let bytes = image.bytes();
    let model = image.model();
    let stub = find_stub(bytes, model)?;
    let unpacked = follow_fixer(bytes, &stub, model.kind)
        .and_then(|finished| restore(image, &stub, &finished, origin));

    match unpacked {
        Ok(unpacked) => Some(unpacked),
        Err(refusal) => Some(Unpacked::refused(NAME, None, refusal)),
    }
}

fn original_code(image: &PeImage<'_>) -> Option<Vec<Range<usize>>> {
    let model = image.model();
    let stub = find_stub(image.bytes(), model)?;

    Some(
        model
            .sections
            .iter()
            .map(|section| section.range())
            .filter(|section| section.end <= stub.stub_start)
            .collect(),
    )
}

fn fixer(image: &PeImage<'_>) -> Option<usize> {
    find_stub(image.bytes(), image.model()).map(|stub| stub.fixer)
}

fn fixer_exit(code: &[u8]) -> Option<usize> {
    (1..code.len()).find_map(|at| {
        let distance = read_u32(code, at).ok()? as usize;
        let exit = REL32_LEN.checked_add(distance)?; // fixer patches own start: jmp +distance
        let found = code.get(at - 1) == Some(&MOV_REG_IMM32)
            && (at..at.saturating_add(MAX_EPILOGUE)).contains(&exit)
            && code.get(exit) == Some(&JUMP_REL32);

        found.then_some(exit)
    })
}

fn find_stub(bytes: &[u8], model: &PeModel) -> Option<Stub> {
    let first_section = model.sections.first()?.virtual_address().as_usize();
    model
        .sections
        .iter()
        .skip(1)
        .rev()
        .filter(|section| section.is_executable())
        .find_map(|section| stub_in_section(bytes, section, model.kind, first_section))
}

fn stub_in_section(
    bytes: &[u8],
    section: &SectionModel,
    kind: PeKind,
    first_section: usize,
) -> Option<Stub> {
    let Range { start, end } = section.range_in(bytes);
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
    let jump = data.checked_sub(REL32_LEN)?;
    (*bytes.get(jump)? == JUMP_REL32).then_some(())?;

    let field = |offset: usize| -> Option<usize> {
        let offset = offset.checked_add(kind.pointer_width() - 4)?; // after qword on x64
        Some(read_u32(bytes, data.checked_add(offset)?).ok()? as usize)
    };

    (relative(bytes, data, data)? == first_section).then_some(())?;

    let fixer = relative(bytes, jump.checked_add(1)?, data)?;
    (fixer > first_section && fixer < stub_start).then_some(())?;

    let relocation_size = field(DATA_RELOCATION_SIZE)?;
    let relocation_rva = match relocation_size {
        0 => 0, // exes end the block here
        _ => field(DATA_RELOCATION_RVA)?,
    };

    Some(Stub {
        first_section,
        stub_start,
        relocation_size,
        relocation_rva,
        fixer,
    })
}

fn follow_fixer(bytes: &[u8], stub: &Stub, kind: PeKind) -> Step<Finished> {
    if bytes.get(stub.fixer) != Some(&JUMP_REL32) {
        return Err(Refusal(
            "the import fixer does not start with the jump it writes when it is done",
        ));
    }

    need(
        fixer_exit_data(bytes, stub, kind),
        "the import fixer's exit does not lead to an entry point and import list in the program",
    )
}

fn fixer_exit_data(bytes: &[u8], stub: &Stub, kind: PeKind) -> Option<Finished> {
    let target = |at: usize| -> Option<usize> {
        (*bytes.get(at)? == JUMP_REL32).then_some(())?;
        relative(bytes, at.checked_add(1)?, at.checked_add(REL32_LEN)?)
    };

    let last = target(stub.fixer)?;
    let entry = match bytes.get(last..last.checked_add(RETURN_TRUE.len())?)? {
        ending if ending == RETURN_TRUE => None,
        _ => Some(target(last)?),
    };

    let hints_field = last.checked_add(REL32_LEN)?;
    let hints = hints_field.checked_add_signed(signed(bytes, hints_field, kind)?)?;
    let in_image = |rva: usize| (stub.first_section..stub.stub_start).contains(&rva);

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
) -> Step<Unpacked> {
    let model = image.model();
    let base = origin.base;
    let kind = model.kind;
    let mut restored = image.bytes().to_vec();
    let mut report = PackerReport::new(NAME, None);

    let entry = finished.entry.unwrap_or_default();
    let written = u32::try_from(entry)
        .ok()
        .and_then(|entry| write_u32(&mut restored, model.entry_point_offset, entry).ok());
    need(written, "the entry point does not fit the header")?;
    if finished.entry.is_some() {
        report.restored(Part::EntryPoint);
    }

    let ImportBlocks {
        blocks,
        original,
        file_base,
    } = import_blocks(&restored, stub, finished, origin, kind)?;
    let span = iat_span(
        blocks.iter().map(|block| (block.start, block.slots)),
        kind.pointer_width(),
    );
    let (iat, iat_size) = need(span, "the import blocks do not form one address table")?;
    model.clear_directory(&mut restored, IMPORT_DIRECTORY);
    let set = model.set_directory(&mut restored, IAT_DIRECTORY, iat, iat_size);
    need(set, "the address table could not be declared")?;
    if blocks.iter().all(|block| block.listed.is_some()) {
        report.restored(Part::Imports);
    } else {
        report.inferred(Part::Imports, "from the filled address table");
    }

    let resources = restore_resources(&mut restored, model, stub.stub_start);
    record_inferred(
        &mut report,
        Part::ResourceLayout,
        resources,
        "tree placed where msvc puts it",
    );

    let relocations = restore_relocations(&mut restored, model, stub);
    let relocation_section =
        matches!(relocations, Restoration::Restored).then_some(stub.relocation_rva);
    report.record(Part::Relocations, relocations);

    let forwarders = restore_forwarders(&mut restored, model, stub.stub_start);
    record_inferred(
        &mut report,
        Part::ExportForwarders,
        forwarders,
        "found by their text, table placed where msvc puts it",
    );

    let pogo = pogo_parts(&restored, model, stub.stub_start);
    let tls = restore_tls(
        &mut restored,
        model,
        base,
        stub.stub_start,
        pogo.as_deref().and_then(pogo_tls_directory),
    );
    report.record(Part::Tls, tls);

    recover_directories(
        &mut restored,
        model,
        origin.base,
        stub.stub_start,
        &origin.writable_sections(model),
        &mut report,
    ); // load config and the rest the stub's header no longer names

    if unwind_info_erased(&restored, model) {
        report.lost(Part::Unwind);
    }

    let linker_pieces = pogo
        .as_deref()
        .and_then(|parts| pogo_sections(parts, &restored, model, stub.stub_start, finished.entry));
    model.clear_directory(&mut restored, BOUND_IMPORT_DIRECTORY);
    if clear_header_slack(&mut restored) {
        report.notes.push(PACKER_HEADER_BYTES.to_string()); // before new headers need the room
    }
    write_section_table(
        &mut restored,
        model,
        linker_pieces,
        finished.entry,
        relocation_section,
        stub.stub_start,
        &mut report,
    );

    let modules = listed_modules(&blocks);
    let imports = PackerImports::Listed(need(modules, "an import block lies past 4 GiB")?);

    let fresh = original.zip(file_base).and_then(|(original, file_base)| {
        with_initial_data(
            image.bytes(),
            &restored,
            InitialData {
                bytes: &original,
                base: file_base,
            },
            base,
            stub.stub_start,
            &[],
        )
    });

    Unpacked::restored(restored, report, Some(imports), fresh)
}

fn record_inferred(
    report: &mut PackerReport,
    part: Part,
    state: Restoration,
    detail: &'static str,
) {
    match state {
        Restoration::Restored => report.inferred(part, detail),
        other => report.record(part, other),
    }
}

struct ImportBlocks {
    blocks: Vec<IatBlock>,
    original: Option<Vec<u8>>,
    file_base: Option<usize>,
}

fn import_blocks(
    restored: &[u8],
    stub: &Stub,
    finished: &Finished,
    origin: &Origin<'_>,
    kind: PeKind,
) -> Step<ImportBlocks> {
    let scan = |listing: &[u8]| {
        iat_blocks(
            restored,
            listing,
            finished.hints,
            kind,
            origin.base,
            stub.first_section..stub.stub_start,
        )
    };

    let file = origin.read_file();
    let originals = original_images(file, restored.len(), kind);
    let file_base = originals.as_ref().map(|(file_base, _)| *file_base);
    let from_file = originals.and_then(|(_, images)| {
        images
            .filter(|image| matches_memory(image, restored))
            .find_map(|image| {
                scan(&image)
                    .filter(|blocks| blocks.iter().all(|block| block.listed.is_some()))
                    .map(|blocks| (blocks, image))
            })
    });

    let (blocks, original) = match from_file {
        Some((blocks, image)) => (blocks, Some(image)),
        None => (
            need(
                scan(restored),
                "the import blocks the stub fills could not be read",
            )?,
            None,
        ),
    };

    Ok(ImportBlocks {
        blocks,
        original,
        file_base,
    })
}

fn write_section_table(
    restored: &mut [u8],
    model: &PeModel,
    linker_pieces: Option<Vec<PlannedSection>>,
    entry: Option<usize>,
    relocation_section: Option<usize>,
    end: usize,
    report: &mut PackerReport,
) {
    let from_linker = linker_pieces
        .is_some_and(|pieces| replace_first_section(restored, model, &pieces).is_some());

    if from_linker {
        report.restored(Part::SectionTable);
    } else {
        let hints = SectionHints {
            code: entry,
            code_end: None,
            constants: None,
            relocations: relocation_section,
            resources: None,
        };
        let split = split_merged_section(restored, model, &hints, None, None).is_some();

        if split {
            report.inferred(Part::SectionSplit, SPLIT_BY_HEADER);
            report.inferred(Part::SectionNames, NAMED_BY_CONTENTS);
        }
        report.lost(Part::SectionTable);

        if !split {
            return;
        }
    }

    if any_section_unproven(restored, end) {
        report.inferred(Part::SectionFlags, UNPROVEN_FLAGS);
    }
}

fn any_section_unproven(restored: &[u8], end: usize) -> bool {
    let superset = SectionKind::WritableCode.characteristics();

    parse_memory_image(restored).is_ok_and(|image| {
        image.model().sections.iter().any(|section| {
            section.virtual_address().as_usize() < end && section.characteristics() == superset
        })
    })
}

fn listed_modules(blocks: &[IatBlock]) -> Option<Vec<ModuleImports>> {
    blocks
        .iter()
        .map(|block| {
            let function = if block.by_ordinal {
                ImportedFunction::OrdinalFromAddress
            } else {
                ImportedFunction::NameFromAddress
            };

            let (module, functions) = match block.listed.clone() {
                Some((module, functions)) => (Some(module), functions),
                None => (None, vec![function; block.slots]),
            };

            Some(ModuleImports {
                module,
                first_thunk: u32::try_from(block.start).ok()?,
                functions,
            })
        })
        .collect()
}

fn matches_memory(decoded: &[u8], memory: &[u8]) -> bool {
    let same = decoded
        .iter()
        .zip(memory)
        .filter(|(left, right)| left == right)
        .count();
    same.saturating_mul(4) >= decoded.len().saturating_mul(3)
}

fn original_images(
    file: Option<&[u8]>,
    image_size: usize,
    kind: PeKind,
) -> Option<(usize, impl Iterator<Item = Vec<u8>>)> {
    let file = file?;
    let disk = parse_disk_image(file).ok()?;
    let file_base = file_base(file, disk.model())?;
    let section = disk.model().sections.first()?;
    let first = section.virtual_address().as_usize();
    let raw = section.raw_pointer as usize;
    let payload = file.get(raw..raw.checked_add(section.raw_size as usize)?)?;

    let size = usize::from(read_u16(payload, 0).ok()?) << PAGE_SHIFT;
    let packed_size = read_u32(payload, 2).ok()? as usize;
    let stream_end = PAYLOAD_HEADER.checked_add(packed_size)?.min(payload.len()); // lzmat over-count
    let stream = payload.get(PAYLOAD_HEADER..stream_end)?;
    (first.checked_add(size)? <= image_size).then_some(())?;

    let decoders: [Decoder; 2] = [decompress_lzma, lzmat::decompress];

    let images = decoders.into_iter().filter_map(move |decode| {
        let mut image = vec![0; first];
        image.extend(decode(stream, size).ok()?);
        unfilter(image.get_mut(first..)?, kind);
        Some(image)
    });
    Some((file_base, images))
}

fn decompress_lzma(stream: &[u8], size: usize) -> Decoded {
    let [packed, literal_context, rest @ ..] = stream else {
        return Err(DecodeError::Truncated);
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
            CALL_REL32 | JUMP_REL32 => at + 1,
            GROUP_FF if x64 && modrm & RIP_INDIRECT_MASK == CALL_MODRM => at + 2,
            LEA if x64 && modrm & MODRM_DISP32_MASK == MODRM_DISP32 => at + 2, // lea reg, [rip + x]
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

fn holds_name(listing: &[u8], at: usize) -> bool {
    read_c_string(listing, at)
        .is_some_and(|(name, _)| name.bytes().all(|byte| byte.is_ascii_graphic()))
}

struct HintListing<'a> {
    memory: &'a [u8],
    listing: &'a [u8],
    kind: PeKind,
    image: Range<usize>, // as addresses
    program: Range<usize>,
    kept_names: bool,
}

impl HintListing<'_> {
    fn filled(&self, at: usize) -> bool {
        read_pointer(self.memory, at, self.kind)
            .is_ok_and(|value| resolved_import(value, &self.image))
    }

    fn block_at(&self, cursor: usize, delta_at: usize, blocks: &[IatBlock]) -> Option<IatBlock> {
        let width = self.kind.pointer_width();
        let name = delta_at.checked_add(width)?;
        let start = cursor.checked_add_signed(signed(self.listing, delta_at, self.kind)?)?;
        let erased =
            self.listing.get(name..name.checked_add(MIN_HINT_ENTRY)?)? == [0; MIN_HINT_ENTRY];
        let named = if self.kept_names {
            holds_name(self.listing, name)
        } else {
            erased
        };
        let fits = named
            && self.program.contains(&start)
            && start.is_multiple_of(width)
            && self.filled(start)
            && !self.filled(start.checked_sub(width)?);
        fits.then_some(())?;

        let slots = (0..MAX_IMPORTS).find(|slot| !self.filled(start + slot * width))?;
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
    }

    fn next_delta(
        &self,
        cursor: usize,
        delta_at: usize,
        slots: usize,
        blocks: &[IatBlock],
    ) -> Option<usize> {
        let first_candidate = delta_at
            .checked_add(self.kind.pointer_width())?
            .checked_add(MIN_HINT_ENTRY.checked_mul(slots.checked_add(1)?)?)?
            .checked_add(1)?;
        let last_candidate = first_candidate
            .checked_add(MAX_HINT_ENTRY.checked_mul(slots.checked_add(1)?)?)?
            .min(self.listing.len());
        let mut next: Option<(usize, usize)> = None;

        for at in first_candidate..last_candidate {
            if read_u32(self.listing, at).is_ok_and(|value| value == HINTS_END) {
                return next.map_or(Some(at), |(record, _)| Some(record));
            }

            let Some(block) = self.block_at(cursor, at, blocks) else {
                continue;
            };

            match next {
                Some((_, start)) if start != block.start => return None, // two records name different tables
                Some(_) => {} // later records repeat the delta when tables touch
                None => next = Some((at, block.start)),
            }
        }

        next.map(|(record, _)| record)
    }
}

fn iat_blocks(
    memory: &[u8],
    listing: &[u8],
    hints: usize,
    kind: PeKind,
    base: usize,
    program: Range<usize>,
) -> Option<Vec<IatBlock>> {
    let width = kind.pointer_width();
    let hint_listing = HintListing {
        memory,
        listing,
        kind,
        image: base..base.saturating_add(program.end),
        program,
        kept_names: holds_name(listing, hints.checked_add(width)?),
    };

    let mut blocks = Vec::new();
    let mut cursor = hints;
    let mut delta_at = hints;

    for _ in 0..MAX_IMPORT_DESCRIPTORS {
        if read_u32(listing, delta_at).ok()? == HINTS_END {
            return (!blocks.is_empty()).then_some(blocks);
        }

        let mut block = hint_listing.block_at(cursor, delta_at, &blocks)?;
        cursor = block.start.checked_add(block.slots.checked_mul(width)?)?;

        if let Some((module, functions, next)) = hint_listing
            .kept_names
            .then(|| listed_hints(listing, delta_at.checked_add(width)?))
            .flatten()
        {
            (functions.len() == block.slots).then_some(())?;
            block.listed = Some((module, functions));
            blocks.push(block);
            delta_at = next;
            continue;
        }

        let next = hint_listing.next_delta(cursor, delta_at, block.slots, &blocks)?;
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
    for _ in 0..MAX_IMPORTS {
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
    let Some(directory) = model.directory(restored, RESOURCE_DIRECTORY) else {
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
        return Restoration::Lost;
    };

    let placed = place(restored, start, &tree.bytes)
        .and_then(|()| model.set_directory(restored, RESOURCE_DIRECTORY, start, tree.bytes.len()));
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
        .and_then(|extent| model.set_directory(restored, RESOURCE_DIRECTORY, start, extent));
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
        .min()?; // msvc: tree first, before the leaves

    let mut start = lowest - lowest % PAGE_SIZE;
    loop {
        restored
            .get(start..lowest)?
            .iter()
            .all(|byte| *byte == 0)
            .then_some(())?;
        if start + tree.bytes.len() <= lowest {
            return Some(start);
        }

        start = start.checked_sub(PAGE_SIZE)?;
    }
}

fn resource_extent(restored: &[u8], start: usize, end: usize) -> Option<usize> {
    let tree = walk_resources(restored, start)?;
    let last = tree
        .data_entries
        .iter()
        .filter_map(|entry| {
            let (_, rva, size) = resource_leaf(restored, start, *entry)?;
            (start..end)
                .contains(&rva)
                .then(|| rva.checked_add(size))
                .flatten()
        })
        .max()?;

    Some((last - start).next_multiple_of(RESOURCE_SIZE_ALIGNMENT))
}

fn restore_relocations(restored: &mut [u8], model: &PeModel, stub: &Stub) -> Restoration {
    let (size, start) = (stub.relocation_size, stub.relocation_rva);

    if size == 0 {
        model.clear_directory(restored, BASERELOC_DIRECTORY);
        return if model.is_dll {
            Restoration::Absent
        } else {
            Restoration::Lost // mpress strips them from exes
        };
    }

    let kind = model.kind.relocation_type();

    let in_place =
        start.saturating_add(size) <= stub.stub_start && relocations_intact(restored, start, size); // <= 2.05 keeps the original blocks
    let table = if in_place {
        restored
            .get(start..start.saturating_add(size))
            .map(<[u8]>::to_vec)
    } else {
        decode_relocations(restored, start, size, stub.stub_start).and_then(|positions| {
            let entries = positions
                .into_iter()
                .map(|rva| Some((u32::try_from(rva).ok()?, kind)))
                .collect::<Option<Vec<_>>>()?;
            relocation_blocks(&entries)
        })
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
        let table_end = start.saturating_add(table.len());
        if let Some(tail) = restored.get_mut(table_end..start.saturating_add(size)) {
            tail.fill(0);
        }
        model.set_directory(restored, BASERELOC_DIRECTORY, start, table.len())?;

        let flags = read_u16(restored, model.dll_characteristics_offset).ok()?;
        write_u16(
            restored,
            model.dll_characteristics_offset,
            flags | DYNAMIC_BASE,
        )
        .ok()?;
        Some(Restoration::Restored)
    });

    restored_or_cleared(restored, model, BASERELOC_DIRECTORY, written)
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
    if model.kind != PeKind::Pe32Plus {
        return false;
    }

    let Some(table) = model.directory(bytes, EXCEPTION_DIRECTORY) else {
        return false;
    };

    let start = table.rva().as_usize();
    let held = bytes.len().saturating_sub(start) / RUNTIME_FUNCTION_SIZE;
    let count = (table.size() as usize / RUNTIME_FUNCTION_SIZE).min(held); // the size field is the packer's

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
    let Some(copy) = model.directory(restored, EXPORT_DIRECTORY) else {
        return Restoration::Absent;
    };

    let copy = copy.rva().as_usize();
    let forwarders = export_forwarders(restored, copy, |rva| {
        rva < end && is_forwarder(restored, rva)
    });
    if forwarders.is_empty() {
        return Restoration::Absent;
    }

    let rebuilt =
        linker_export_layout(restored, copy, &forwarders, None).and_then(|(start, block)| {
            place(restored, start, &block)?;

            let size = block.len().checked_next_multiple_of(EXPORT_ALIGNMENT)?;
            model.set_directory(restored, EXPORT_DIRECTORY, start, size)
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

pub(super) struct Mpress;

impl Packer for Mpress {
    fn unpack(&self, image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
        unpack(image, origin)
    }

    fn original_code(&self, image: &PeImage<'_>, _base: usize) -> Option<Vec<Range<usize>>> {
        original_code(image)
    }

    fn import_fixer(&self, image: &PeImage<'_>) -> Option<usize> {
        fixer(image)
    }

    fn import_fixer_exit(&self, code: &[u8]) -> Option<usize> {
        fixer_exit(code)
    }
}
