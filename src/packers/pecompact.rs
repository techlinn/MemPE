use std::collections::HashSet;
use std::ops::Range;
use std::sync::Arc;

use super::{NAMED_BY_CONTENTS, Packer, UNPROVEN_FLAGS};
use crate::pe::RELOCATION_KIND_SHIFT;
use crate::pe::bytes::{read_u16, read_u32, relocation_block, relocation_words, write_u32};
use crate::pe::parse::parse_disk_image;
use crate::pe::{
    BASERELOC_DIRECTORY, BOUND_IMPORT_DIRECTORY, EXPORT_DIRECTORY, HINT_SIZE,
    IMPORT_DESCRIPTOR_SIZE, IMPORT_IAT_OFFSET, IMPORT_NAME_OFFSET, MAX_IMPORT_DESCRIPTORS,
    MAX_IMPORTS, MODULE_ALIGNMENT, PeImage, PeKind, PeModel, RELOCATION_BLOCK_HEADER,
    RELOCATION_HIGHLOW, RELOCATION_OFFSET_MASK, Rva, TLS_DIRECTORY, TLS_DIRECTORY_PE32,
    TLS_POINTER_FIELDS, map_disk_image,
};
use crate::unpack::codecs::bitstream::{ByteTags, WordTags};
use crate::unpack::codecs::call_filter::{self, CallFilter, Stored};
use crate::unpack::codecs::{aplib, brieflz, ffce, jcalg1, lzma};
use crate::unpack::tables::{
    CoffGroup, MAX_RELOCATION_BLOCK, PlannedSection, Restoration, SectionHints, SectionKind,
    THUNK_SIZE, apply_listed_imports, code_stores_into, export_forwarders, first_section_range,
    iat_filled, iat_start, linker_bounds, linker_export_layout, linker_export_start,
    listed_imports, lowest_leaf_below, name_sections, place, pogo_parts, pogo_sections,
    pogo_tls_directory, read_c_string, relocate, relocated_fields, relocation_blocks,
    replace_first_section, resource_layout, restore_load_config, restore_moved_resources,
    restore_tls, restored_or_cleared, safeseh_field, unique,
};
use crate::unpack::{
    ImportedFunction, InitialData, ModuleImports, Origin, PackerId, PackerReport, Part, Refusal,
    Step, Unpacked, file_base, find_pattern, find_patterns, hex, need, pattern_at,
    with_initial_data,
};

const NAME: PackerId = PackerId::PeCompact;
const SIGNATURE: &[u8] = b"PEC2"; // in PointerToRelocations
const SIGNATURE_OFFSET: usize = 0x18;
const BUILD_OFFSET: usize = 0x1C;
const HANDLER_BODY: &str = hex("8B 54 24 04 8B 52 0C C6 02 E9 83 C2 05 2B CA 89 4A FC 33 C0 C3"); // patches faulting insn to jmp loader
const HANDLER_PREFIX: usize = 0x0E; // 3 insns before body
const STUB_CODE: usize = 0x18;
const ENTRY_STUB: &str = hex("B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00"); // mov eax, handler / push / push fs:[0]
const STUB_REBASED: usize = 5; // rebased operand
const STUB_MARKERS: [&[u8]; 2] = [b"PECompact2\0", b"PEC2\0"];
const LOADER_INFO_SIZE: usize = 0x24; // precedes handler
const LOADER_PACKED: usize = 0x00;
const LOADER_SIZE: usize = 0x04;
const LOADER_ENTRY: usize = 0x08;
const LOADER_DECODER: usize = 0x0C;
const HOST_INFO_SIZES: Range<usize> = 0x50..0x100;
const HOST_IMAGE_BASE: usize = 0x04;
const HOST_ENTRY: usize = 0x0C;
const HOST_DECODERS: usize = 0x30; // before the host info
const HOST_IMPORTS: usize = 0x34;
const HOST_OVERFLOWS: usize = 0x4C; // before the host info
const HOST_RELOCATIONS: usize = 0x38;
const HOST_BLOCK_COUNT: usize = 0x3C;
const HOST_STUB: usize = 0x40;
const HOST_SAVED_BYTES: usize = 0x44;
const BLOCK_SIZE: usize = 0x1C;
const BLOCK_DESTINATION: usize = 0x04;
const BLOCK_LENGTH: usize = 0x08;
const BLOCK_ORIGINAL_LENGTH: usize = 0x0C;
const BLOCK_FLAGS: usize = 0x10;
const BLOCK_EXTRA: usize = 0x12;
const BLOCK_OVERFLOW: usize = 0x14; // spill outside section
const BLOCK_OVERFLOW_INDEX: usize = 0x18;
const BLOCK_DECODER: usize = 0x1A;
const MAX_BLOCKS: usize = 1_024;
const MERGED: u16 = 0x0002; // appended to the first section
const FILTERED: u16 = 0x0008; // calls and jumps made absolute
const ENCODED: u16 = 0x0010;
const MARKED: u16 = 0x0200; // call bytes that looked like marks
const MAX_MARKS: usize = 1 << 20;
const LZMA_PROBABILITY_INIT: &str = hex("00 03 00 00");
const FFCE_FAR_MATCH: &str = hex("3D 01 80 00 00"); // cmp eax, 8001h
const APLIB_FAR_MATCH: &str = hex("3D 00 7D 00 00"); // cmp eax, 7D00h
const BYTE_TAG_REFILL: &str = hex("02 D2"); // add dl, dl
const COPY_DWORDS: &str = hex("C1 E9 02 83 E0 03 F3 A5"); // shr ecx, 2 / and eax, 3 / rep movsd
const SWAP_BYTES: &str = hex("C1 E3 10 81 E2 00 FF 00 00"); // shl ebx, 16 / and edx, 0FF00h
const CRC32_POLYNOMIAL: &str = hex("35 20 83 B8 ED"); // xor eax, 0EDB88320h
const ELF_HASH_MASK: &str = hex("25 00 00 00 F0"); // and eax, 0F0000000h
const MAX_DECODERS: usize = 16;
const STORED_HEADER: usize = 4; // u32 length
const CHECKSUM_SIZE: usize = 4;
const LZMA_PROPERTIES: usize = 4; // after the unpacked size
const LZMA_STREAM: usize = 9; // properties byte and dictionary size
const LZMA_SIZE_FIELD: usize = 8;
const LEGACY_LZMA_SIZE: usize = 4; // 2.3: probability size first
const LEGACY_LZMA_PROPERTIES: usize = 12; // then pb, lp, lc
const LEGACY_LZMA_STREAM: usize = 15;
const MARK_SIZE: usize = 2;
const MARK_ENTRY: usize = 4; // u32 rva, zero ends the list
const DECODER_ENTRY: usize = 4;
const COMPRESSORS: [Codec; 6] = [
    Codec::Ffce,
    Codec::Aplib { word_tags: true },
    Codec::Aplib { word_tags: false },
    Codec::BriefLz,
    Codec::Jcalg1,
    Codec::Lzma,
];

#[derive(Clone, Copy)]
enum Codec {
    Checksum,
    Copy,
    Invert,
    Ffce,
    Aplib { word_tags: bool },
    BriefLz,
    Jcalg1,
    Lzma,
}

struct Block {
    source: usize,
    destination: usize,
    length: usize,
    original_length: usize,
    flags: u16,
    extra: u16,
    overflow: usize,
    overflow_index: usize,
    decoder: usize,
}

struct PackedImage {
    mapped: Vec<u8>,
    base: usize,
    loader: Vec<u8>,
    host: usize,
    blocks: Vec<Block>,
    stored: Vec<Range<usize>>,
    original_end: usize,
    in_memory: bool,
}

fn original_code(image: &PeImage<'_>, base: usize) -> Option<Vec<Range<usize>>> {
    let bytes = image.bytes();
    let model = image.model();
    let entry = read_u32(bytes, model.entry_point_offset).ok()? as usize;
    let handler = match pattern_at(bytes, entry, ENTRY_STUB) {
        true => (read_u32(bytes, entry.checked_add(1)?).ok()? as usize).checked_sub(base)?,
        false => find_handler(bytes, model)?,
    };
    let loader = model
        .sections
        .iter()
        .map(|section| section.range())
        .find(|section| section.contains(&handler))?;

    Some(
        model
            .sections
            .iter()
            .map(|section| section.range())
            .filter(|section| section.start < loader.start) // stub in program code
            .collect(),
    )
}

fn unpack(image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
    let model = image.model();
    let header = model.sections.first()?.header_offset;
    let tagged = image
        .bytes()
        .get(header.checked_add(SIGNATURE_OFFSET)?..)?
        .starts_with(SIGNATURE);
    (tagged || find_handler(image.bytes(), model).is_some()).then_some(())?; // tag optional

    let build = match tagged {
        true => read_u32(image.bytes(), header + BUILD_OFFSET).unwrap_or(0),
        false => 0,
    };
    let version = (build != 0).then(|| format!("build {build}"));
    let packed = origin
        .read_file()
        .and_then(|file| PackedImage::open(file, image))
        .or_else(|| PackedImage::from_memory(image));
    let Some(packed) = packed else {
        return Some(Unpacked::detected_only(
            NAME,
            version,
            "its loader tables could not be read",
        ));
    };

    match restore(image, origin, &packed, version.clone()) {
        Ok(unpacked) => Some(unpacked),
        Err(refusal) => Some(Unpacked::refused(NAME, version, refusal)),
    }
}

fn restore(
    image: &PeImage<'_>,
    origin: &Origin<'_>,
    packed: &PackedImage,
    version: Option<String>,
) -> Step<Unpacked> {
    let model = image.model();
    let end = packed.original_end;
    let mut restored = image.bytes().to_vec();
    let original = packed.original_image();

    let entry = need(
        packed.host_field(HOST_ENTRY),
        "the loader holds no entry point",
    )?;
    if entry >= end {
        return Err(Refusal("the loader's entry point is past the program"));
    }

    let unpacked = stub_finished(image, packed, original.is_some())?;

    let first = need(model.sections.first(), "the image has no sections")?;
    let image_start = first.virtual_address().as_usize();
    let program = image_start..end;
    let from_packed = copy_program(&mut restored, &program, original.as_deref(), unpacked)?;

    let mut report = PackerReport::new(NAME, version);
    if from_packed {
        let source = match packed.in_memory {
            true => "from the packed sections",
            false => "from the packed file",
        };
        report.restored_with(Part::CodeAndData, source);
    } else if packed.in_memory {
        report.inferred(
            Part::CodeAndData,
            "taken as unpacked because the stock entry stub is gone",
        );
    }

    let written = u32::try_from(entry)
        .ok()
        .and_then(|entry| write_u32(&mut restored, model.entry_point_offset, entry).ok());
    need(written, "the entry point does not fit the header")?;
    report.restored(Part::EntryPoint);

    let modules = listed_modules(packed, original.as_deref(), &restored, model, from_packed);
    let imports = modules.and_then(|modules| apply_listed_imports(&mut restored, model, modules));
    match (&imports, &original) {
        (Some(_), Some(_)) => report.restored(Part::Imports),
        (Some(_), None) => report.inferred(
            Part::Imports,
            "names matched by resolved address among strings left in memory",
        ),
        (None, _) => report.failed(Part::Imports),
    }

    let relocations = restore_relocations(
        &mut restored,
        model,
        packed,
        original.as_deref().unwrap_or(image.bytes()), // delta list left in place
    );
    report.record(Part::Relocations, relocations);

    if from_packed {
        let delta = origin.base.wrapping_sub(packed.base);
        rebase_program(&mut restored, model, &program, delta, &mut report)?;
    }

    let pogo = pogo_parts(&restored, model, end);
    let (sections, from_linker) =
        planned_sections(packed, &restored, model, entry, pogo.as_deref());

    let ranges = match &sections {
        Some(sections) => sections
            .iter()
            .map(|piece| piece.start..piece.end)
            .collect(),
        None => packed.stored.clone(),
    };

    let layout = resource_layout(&restored, model, std::iter::empty());
    let resources = restore_moved_resources(&mut restored, model, &ranges, end, layout, None);
    report.record(Part::Resources, resources);

    let exports = restore_exports(&mut restored, model, end);
    report.record(Part::Exports, exports);

    restore_load_config(
        &mut restored,
        model,
        origin.base,
        packed.base,
        end,
        &origin.writable_sections(model),
        &mut report,
    );

    if directory_moved(&restored, model, TLS_DIRECTORY, end) {
        let linker_place = pogo.as_deref().and_then(pogo_tls_directory);
        restore_moved_tls(
            &mut restored,
            model,
            origin.base,
            end,
            linker_place,
            &mut report,
        );
    }

    match cover_stripped_pointers(&mut restored, model) {
        Some(true) => report.inferred(
            Part::Relocations,
            "entries added for the TLS and handler table pointers",
        ),
        Some(false) => {}
        None => report.partly_failed(Part::Relocations, "directory pointers are not in the table"),
    }

    write_section_table(&mut restored, model, sections, from_linker, &mut report);

    model.clear_directory(&mut restored, BOUND_IMPORT_DIRECTORY);

    let fresh = original.filter(|_| !from_packed).and_then(|original| {
        with_initial_data(
            image.bytes(),
            &restored,
            InitialData {
                bytes: &original,
                base: packed.base,
            },
            origin.base,
            end,
            &[],
        )
    });

    Unpacked::restored(restored, report, imports, fresh)
}

fn stub_finished(image: &PeImage<'_>, packed: &PackedImage, decoded: bool) -> Step<bool> {
    let stub = need(
        packed.host_field(HOST_STUB),
        "the loader holds no stub address",
    )?;
    let stub_code = stub + STUB_REBASED..stub + STUB_CODE;

    Ok(match packed.in_memory {
        // stub restored last
        true => !decoded && !pattern_at(image.bytes(), stub, ENTRY_STUB),
        false => image.bytes().get(stub_code.clone()) != packed.mapped.get(stub_code),
    })
}

fn copy_program(
    restored: &mut [u8],
    program: &Range<usize>,
    original: Option<&[u8]>,
    unpacked: bool,
) -> Step<bool> {
    match (unpacked, original) {
        (true, _) => Ok(false),
        (false, Some(original)) => {
            let copied = restored
                .get_mut(program.clone())
                .zip(original.get(program.clone()))
                .map(|(to, from)| to.copy_from_slice(from));
            need(copied, "the packed data is shorter than the program")?;
            Ok(true)
        }
        (false, None) => Err(Refusal("the stub had not finished unpacking")),
    }
}

fn listed_modules(
    packed: &PackedImage,
    original: Option<&[u8]>,
    restored: &[u8],
    model: &PeModel,
    from_packed: bool,
) -> Option<Vec<ModuleImports>> {
    let import_list = packed.host_field(HOST_IMPORTS);

    match original {
        Some(mut original) => import_list.and_then(|start| {
            let modules = listed_imports(start, &mut original)?;
            (from_packed || iat_filled(restored, &modules, PeKind::Pe32, true)).then_some(modules)
        }),
        None => import_list.and_then(|start| imports_left_in_memory(restored, model, start)),
    }
}

fn rebase_program(
    restored: &mut [u8],
    model: &PeModel,
    program: &Range<usize>,
    delta: usize,
    report: &mut PackerReport,
) -> Step<()> {
    let mut moved = restored.to_vec();
    let rebased = relocate(&mut moved, restored, model, |value, _| {
        value.wrapping_add(delta)
    });
    if delta != 0 && rebased.is_none() {
        report.partly_failed(Part::Relocations, "pointers still for the file's base");
    }

    let copied = restored
        .get_mut(program.clone())
        .zip(moved.get(program.clone()))
        .map(|(to, from)| to.copy_from_slice(from));
    need(copied, "the rebased program does not fit the image")?;
    Ok(())
}

fn planned_sections(
    packed: &PackedImage,
    restored: &[u8],
    model: &PeModel,
    entry: usize,
    pogo: Option<&[CoffGroup]>,
) -> (Option<Vec<PlannedSection>>, bool) {
    let merged = packed.original_sections(restored, model, entry);
    let linker_pieces = merged.as_ref().and(pogo).and_then(|parts| {
        pogo_sections(
            parts,
            restored,
            model,
            first_section_range(model)?.end,
            Some(entry),
        )
    });
    let from_linker = linker_pieces.is_some();

    (linker_pieces.or(merged), from_linker)
}

fn write_section_table(
    restored: &mut [u8],
    model: &PeModel,
    sections: Option<Vec<PlannedSection>>,
    from_linker: bool,
    report: &mut PackerReport,
) {
    let Some(sections) = sections else {
        report.lost(Part::SectionFlags); // all sections made writable
        return;
    };

    let unproven = sections
        .iter()
        .any(|piece| piece.kind == SectionKind::WritableCode);
    if replace_first_section(restored, model, &sections).is_none() {
        report.lost(Part::SectionTable);
        return;
    }

    match from_linker {
        true => report.restored(Part::SectionTable),
        false => {
            report.restored(Part::SectionSplit);
            report.inferred(Part::SectionNames, NAMED_BY_CONTENTS);
            report.lost(Part::SectionTable);
        }
    }

    if unproven {
        report.inferred(Part::SectionFlags, UNPROVEN_FLAGS);
    }
}

impl PackedImage {
    fn open(file: &[u8], image: &PeImage<'_>) -> Option<Self> {
        let disk = parse_disk_image(file).ok()?;
        let model = disk.model();
        let memory = image.model();
        let entry = read_u32(file, model.entry_point_offset).ok()? as usize;
        let same_image = model.image_size == memory.image_size
            && read_u32(image.bytes(), memory.entry_point_offset).ok()? as usize == entry;
        same_image.then_some(())?;

        let mapped = map_disk_image(file, model.image_size as usize)?;
        let packed = Self::load(mapped, model, memory, false)?;
        let base = file_base(file, model)?;
        (packed.base == base).then_some(packed)
    }

    fn from_memory(image: &PeImage<'_>) -> Option<Self> {
        let packed = Self::load(image.bytes().to_vec(), image.model(), image.model(), true)?;
        packed.tables_fit_image().then_some(packed) // no file to check the base against
    }

    fn tables_fit_image(&self) -> bool {
        let size = self.mapped.len();
        let fits = |start: usize, length: usize| {
            start.checked_add(length).is_some_and(|stop| stop <= size)
        };
        let block_fits = |block: &Block| {
            let has = |flag: u16| block.flags & flag != 0;
            let inline = block.length.checked_sub(block.overflow);

            (!has(ENCODED)
                || inline.is_some_and(|inline| fits(block.source, inline))
                    && fits(block.destination, block.original_length))
                && (!has(MERGED)
                    || fits(block.source, block.length) && fits(block.destination, block.length))
                && (!has(FILTERED) || fits(block.source, block.length))
                && (!has(MARKED) || fits(block.source, MARK_ENTRY))
        };

        self.base != 0
            && self.base.is_multiple_of(MODULE_ALIGNMENT as usize)
            && self.blocks.iter().all(block_fits)
    }

    fn load(mapped: Vec<u8>, layout: &PeModel, memory: &PeModel, in_memory: bool) -> Option<Self> {
        (layout.kind == PeKind::Pe32).then_some(())?;
        let handler = find_handler(&mapped, layout)?; // by its body, entry stubs vary
        let info = handler.checked_sub(LOADER_INFO_SIZE)?;
        let field =
            |offset: usize| Some(read_u32(&mapped, info.checked_add(offset)?).ok()? as usize);

        let handler_rva = Rva(u32::try_from(handler).ok()?);
        let holds_handler = |model: &PeModel| {
            model
                .sections
                .iter()
                .find(|section| section.contains_rva(handler_rva))
                .map(|section| section.virtual_address().as_usize())
        };
        let original_end = holds_handler(memory)?;
        (holds_handler(layout)? <= info).then_some(())?; // info block sits with its handler

        let packed_loader = mapped.get(field(LOADER_PACKED)?..)?;
        let decoder = mapped.get(field(LOADER_DECODER)?..info)?;
        let loader_size = field(LOADER_SIZE).filter(|size| *size <= mapped.len())?;
        let loader = decode_stream(decoder, packed_loader, loader_size)?;
        let loader_entry = field(LOADER_ENTRY).filter(|entry| *entry <= loader.len())?;
        let host = host_info(&loader, loader_entry)?;

        let stored = layout
            .sections
            .iter()
            .map(|section| section.range())
            .filter(|range| range.start < original_end)
            .collect();
        let mut packed = Self {
            mapped,
            base: 0,
            loader,
            host,
            blocks: Vec::new(),
            stored,
            original_end,
            in_memory,
        };
        packed.base = packed.host_field(HOST_IMAGE_BASE)?;
        packed.blocks = packed.read_blocks()?;
        Some(packed)
    }

    fn host_field(&self, offset: usize) -> Option<usize> {
        Some(read_u32(&self.loader, self.host.checked_add(offset)?).ok()? as usize)
    }

    fn read_blocks(&self) -> Option<Vec<Block>> {
        let count = self.host_field(HOST_BLOCK_COUNT)?;
        (count <= MAX_BLOCKS).then_some(())?;
        let first = self
            .host
            .checked_add(usize::from(read_u16(&self.loader, self.host).ok()?))?;

        (0..count)
            .map(|index| {
                let at = first.checked_add(index.checked_mul(BLOCK_SIZE)?)?;
                let word = |offset: usize| read_u16(&self.loader, at + offset).ok();
                let dword =
                    |offset: usize| Some(read_u32(&self.loader, at + offset).ok()? as usize);
                Some(Block {
                    source: dword(0)?,
                    destination: dword(BLOCK_DESTINATION)?,
                    length: dword(BLOCK_LENGTH)?,
                    original_length: dword(BLOCK_ORIGINAL_LENGTH)?,
                    flags: word(BLOCK_FLAGS)?,
                    extra: word(BLOCK_EXTRA)?,
                    overflow: dword(BLOCK_OVERFLOW)?,
                    overflow_index: usize::from(word(BLOCK_OVERFLOW_INDEX)?),
                    decoder: usize::from(word(BLOCK_DECODER)?),
                })
            })
            .collect()
    }

    fn decoders(&self) -> Option<Vec<&[u8]>> {
        let table = self.host.checked_sub(self.host_field(HOST_DECODERS)?)?;
        let starts = (0..MAX_DECODERS)
            .map_while(|index| {
                let entry = table.checked_add(index * DECODER_ENTRY)?;
                let offset = read_u32(&self.loader, entry).ok()? as usize;
                (offset != 0).then(|| table.checked_add(offset)).flatten()
            })
            .collect::<Vec<_>>();

        starts
            .iter()
            .map(|start| {
                let end = starts
                    .iter()
                    .copied()
                    .filter(|other| other > start)
                    .min()
                    .unwrap_or(self.host);
                self.loader.get(*start..end)
            })
            .collect()
    }

    fn overflow(&self, index: usize, length: usize) -> Option<&[u8]> {
        let mut at = self.host.checked_sub(self.host_field(HOST_OVERFLOWS)?)?;
        for _ in 0..index {
            let skipped = read_u32(&self.loader, at).ok()? as usize;
            at = at.checked_add(STORED_HEADER)?.checked_add(skipped)?;
        }

        (read_u32(&self.loader, at).ok()? as usize == length).then_some(())?;
        let start = at.checked_add(STORED_HEADER)?;
        self.loader.get(start..start.checked_add(length)?)
    }

    fn decode_block(&self, block: &Block, stream: &[u8]) -> Option<Vec<u8>> {
        let decoders = self.decoders()?;
        let chain = decoders.get(block.decoder..)?;
        let mut data = stream.to_vec();

        for (position, decoder) in chain.iter().enumerate().rev() {
            data = match Codec::identify(decoder, &data) {
                Some(Codec::Checksum) => unwrap_checksum(&data)?,
                _ if position == 0 => decode_stream(decoder, &data, block.original_length)?,
                _ => return None, // only checksums chain after the compressor
            };
        }

        (data.len() == block.original_length).then_some(data)
    }

    fn original_image(&self) -> Option<Vec<u8>> {
        let mut packed = self.mapped.clone();
        let stub = self.host_field(HOST_STUB)?;
        let saved = self.host_field(HOST_SAVED_BYTES)?;
        let length = stub_length(&self.mapped, stub);
        let covered = self.mapped.get(saved..saved.checked_add(length)?)?;
        packed
            .get_mut(stub..stub.checked_add(length)?)?
            .copy_from_slice(covered); // entry stub overwrote packed data

        let merged = self.decoded_blocks(&packed)?;
        self.unmerged(&packed, &merged)
    }

    fn flagged(&self, flag: u16) -> impl Iterator<Item = &Block> {
        self.blocks
            .iter()
            .filter(move |block| block.flags & flag != 0)
    }

    fn decoded_blocks(&self, packed: &[u8]) -> Option<Vec<u8>> {
        let mut merged = vec![0u8; packed.len()];
        for block in self.flagged(ENCODED) {
            (block.original_length <= packed.len()).then_some(())?;
            let inline = block.length.checked_sub(block.overflow)?;
            let mut stream = packed
                .get(block.source..block.source.checked_add(inline)?)?
                .to_vec();
            if block.overflow != 0 {
                stream.extend_from_slice(self.overflow(block.overflow_index, block.overflow)?); // continues where the section ran out
            }
            let decoded = self.decode_block(block, &stream)?;
            merged
                .get_mut(block.destination..block.destination.checked_add(decoded.len())?)?
                .copy_from_slice(&decoded);
        }

        for block in self.flagged(FILTERED) {
            let code = merged.get_mut(block.source..block.source.checked_add(block.length)?)?;
            call_filter::undo(
                code,
                block.length,
                CallFilter {
                    marks: Some(block.extra.to_le_bytes()), // after a call, after a jump
                    stored: Stored::Be24,
                    counted_from: 0,
                },
            );
        }

        for block in self.flagged(MARKED) {
            let mut ended = false;
            for index in 0..MAX_MARKS {
                let entry = block.source.checked_add(index * MARK_ENTRY)?;
                let rva = read_u32(&self.mapped, entry).ok()? as usize;
                if rva == 0 {
                    ended = true;
                    break;
                }

                merged
                    .get_mut(rva..rva.checked_add(MARK_SIZE)?)?
                    .copy_from_slice(&block.extra.to_le_bytes());
            }
            ended.then_some(())?; // list longer than the cap
        }

        Some(merged)
    }

    fn unmerged(&self, packed: &[u8], merged: &[u8]) -> Option<Vec<u8>> {
        let mut image = vec![0u8; packed.len()];
        let overlaps = |range: &Range<usize>, start: usize, length: usize| {
            start < range.end && range.start < start.saturating_add(length)
        };
        for range in &self.stored {
            let packed_here = self
                .flagged(ENCODED)
                .any(|block| overlaps(range, block.destination, block.original_length))
                || self
                    .flagged(MERGED)
                    .any(|block| overlaps(range, block.source, block.length));
            if !packed_here {
                image
                    .get_mut(range.clone())?
                    .copy_from_slice(packed.get(range.clone())?);
            }
        }

        for block in self.flagged(ENCODED) {
            let decoded_end = block.destination.checked_add(block.original_length)?;
            let kept_end = self
                .flagged(MERGED)
                .map(|moved| moved.destination)
                .filter(|start| (block.destination..decoded_end).contains(start))
                .min()
                .unwrap_or(decoded_end);
            image
                .get_mut(block.destination..kept_end)?
                .copy_from_slice(merged.get(block.destination..kept_end)?);
        }

        for block in self.flagged(MERGED) {
            let piece =
                merged.get(block.destination..block.destination.checked_add(block.length)?)?;
            image
                .get_mut(block.source..block.source.checked_add(block.length)?)?
                .copy_from_slice(piece);
        }

        Some(image)
    }

    fn original_sections(
        &self,
        restored: &[u8],
        model: &PeModel,
        entry: usize,
    ) -> Option<Vec<PlannedSection>> {
        self.flagged(MERGED).next()?;
        let Range {
            start,
            end: packed_end,
        } = first_section_range(model)?;

        let first = self.flagged(ENCODED).map(|block| block.destination).min();
        let starts = self
            .flagged(MERGED)
            .map(|block| block.source)
            .chain(first)
            .filter(|piece| *piece < packed_end)
            .collect::<Vec<_>>();

        let bounds = linker_bounds(restored, model, entry);
        let constants = bounds.and_then(|bounds| {
            let iat = iat_start(restored, self.host_field(HOST_IMPORTS)?)?;
            let next = starts
                .iter()
                .copied()
                .filter(|piece| *piece > iat)
                .min()
                .unwrap_or(packed_end);
            let base = file_base(restored, model)?; // the loader writes the running base there
            let stored = code_stores_into(
                restored,
                base,
                model.kind.bits(),
                &(start..bounds.code_end),
                &(iat..next),
            );
            (starts.contains(&iat) && !stored).then_some(iat) // no store of the program's lands there: constants
        });

        let hints = SectionHints {
            code: Some(entry),
            code_end: bounds.map(|bounds| bounds.code_end),
            constants,
            relocations: self.host_field(HOST_RELOCATIONS),
            resources: lowest_leaf_below(restored, model, self.original_end),
        };
        Some(name_sections(starts, packed_end, &hints, bounds.is_some()))
    }
}

impl Codec {
    fn identify(decoder: &[u8], stream: &[u8]) -> Option<Self> {
        let has = |pattern: &str| find_pattern(decoder, pattern).is_some();
        if has(CRC32_POLYNOMIAL) || has(ELF_HASH_MASK) {
            Some(Self::Checksum)
        } else if has(COPY_DWORDS) {
            Some(Self::Copy)
        } else if has(SWAP_BYTES) {
            Some(Self::Invert)
        } else if stream.starts_with(jcalg1::MAGIC) {
            Some(Self::Jcalg1)
        } else if has(LZMA_PROBABILITY_INIT) {
            Some(Self::Lzma)
        } else if has(FFCE_FAR_MATCH) {
            Some(Self::Ffce)
        } else if has(APLIB_FAR_MATCH) {
            Some(Self::Aplib {
                word_tags: !has(BYTE_TAG_REFILL),
            })
        } else {
            None
        }
    }

    fn decode(self, stream: &[u8], size: usize) -> Option<Vec<u8>> {
        let decoded = match self {
            Self::Checksum => unwrap_checksum(stream),
            Self::Copy => stored_bytes(stream, size).map(<[u8]>::to_vec),
            Self::Invert => stored_bytes(stream, size).map(|bytes| {
                let (words, tail) = bytes.as_chunks::<4>();
                let mut output = words
                    .iter()
                    .flat_map(|word| word.iter().rev().copied())
                    .collect::<Vec<_>>();
                output.extend_from_slice(tail);
                output
            }),
            Self::Ffce => ffce::decompress(stream, size).ok(),
            Self::Aplib { word_tags: true } => {
                aplib::decompress_exact(WordTags::new(stream, 0), size, aplib::Variant::Classic)
                    .ok()
            }
            Self::Aplib { word_tags: false } => {
                aplib::decompress_exact(ByteTags::new(stream), size, aplib::Variant::Classic).ok()
            }
            Self::BriefLz => brieflz::decompress(stream, size).ok(),
            Self::Jcalg1 => jcalg1::decompress(stream, size).ok(),
            Self::Lzma => decompress_lzma(stream, size),
        }?;

        (decoded.len() == size).then_some(decoded)
    }
}

fn decode_stream(decoder: &[u8], stream: &[u8], size: usize) -> Option<Vec<u8>> {
    match Codec::identify(decoder, stream) {
        Some(codec) => codec.decode(stream, size),
        None => unique(
            COMPRESSORS
                .iter()
                .filter_map(|codec| codec.decode(stream, size)),
        ), // decoder without a signature: exactly one codec may fit
    }
}

fn find_handler(bytes: &[u8], model: &PeModel) -> Option<usize> {
    let mut bodies = model
        .sections
        .iter()
        .flat_map(|section| {
            let Range { start, end } = section.range_in(bytes);
            find_patterns(bytes.get(start..end).unwrap_or_default(), HANDLER_BODY)
                .map(move |body| start.saturating_add(body))
        })
        .collect::<Vec<_>>();
    bodies.sort_unstable();
    bodies.dedup(); // sections may overlap

    unique(bodies)?.checked_sub(HANDLER_PREFIX)
}

fn imports_left_in_memory(
    memory: &[u8],
    model: &PeModel,
    start: usize,
) -> Option<Vec<ModuleImports>> {
    let mut found = Vec::new();
    for index in 0..MAX_IMPORT_DESCRIPTORS {
        let descriptor = start.checked_add(index.checked_mul(IMPORT_DESCRIPTOR_SIZE)?)?;
        let field =
            |offset: usize| Some(read_u32(memory, descriptor.checked_add(offset)?).ok()? as usize);
        let (name, iat) = (field(IMPORT_NAME_OFFSET)?, field(IMPORT_IAT_OFFSET)?);
        if name == 0 && iat == 0 {
            break;
        }

        let module = read_c_string(memory, name)?.0;
        let slots = (0..MAX_IMPORTS)
            .take_while(|slot| {
                read_u32(memory, iat.saturating_add(slot * THUNK_SIZE))
                    .is_ok_and(|value| value != 0)
            })
            .count();
        found.push((name, module, iat, slots));
    }

    let listed = Arc::new(leftover_names(
        memory,
        model,
        found.iter().map(|(name, ..)| *name),
    )?);
    let modules = found
        .into_iter()
        .map(|(_, module, iat, slots)| {
            Some(ModuleImports {
                module: Some(module),
                first_thunk: u32::try_from(iat).ok()?,
                functions: vec![ImportedFunction::NameFromAddressAmong(Arc::clone(&listed)); slots],
            })
        })
        .collect::<Option<Vec<_>>>()?;
    (!modules.is_empty()).then_some(modules)
}

fn leftover_names(
    memory: &[u8],
    model: &PeModel,
    module_names: impl Iterator<Item = usize>,
) -> Option<HashSet<String>> {
    let mut holders = Vec::new();
    for at in module_names {
        let holder = model
            .sections
            .iter()
            .map(|section| section.range_in(memory))
            .find(|range| range.contains(&at))?;
        if !holders.contains(&holder) {
            holders.push(holder);
        }
    }

    let identifier =
        |byte: &u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'@' | b'?' | b'$');
    let mut names = HashSet::new();
    for holder in holders {
        let runs = memory
            .get(holder)?
            .split(|byte| !identifier(byte))
            .filter(|run| run.len() > HINT_SIZE)
            .flat_map(|run| (0..=HINT_SIZE).filter_map(move |skip| run.get(skip..))) // a hint can read as letters
            .filter_map(|run| std::str::from_utf8(run).ok())
            .map(str::to_owned);
        names.extend(runs);
    }

    (!names.is_empty()).then_some(names)
}

fn stored_bytes(stream: &[u8], size: usize) -> Option<&[u8]> {
    (read_u32(stream, 0).ok()? as usize == size).then_some(())?;
    stream.get(STORED_HEADER..STORED_HEADER.checked_add(size)?)
}

fn unwrap_checksum(stream: &[u8]) -> Option<Vec<u8>> {
    let length = read_u32(stream, 0).ok()? as usize;
    let end = STORED_HEADER.checked_add(length)?;
    (end.checked_add(CHECKSUM_SIZE)? <= stream.len()).then_some(())?;
    stream.get(STORED_HEADER..end).map(<[u8]>::to_vec)
}

fn host_info(loader: &[u8], entry: usize) -> Option<usize> {
    let distance = read_u32(loader, entry.checked_sub(4)?).ok()? as usize; // stored before the loader's entry
    let start = entry.checked_sub(distance)?;
    [Some(start), start.checked_sub(4)]
        .into_iter()
        .flatten()
        .find(|at| {
            read_u16(loader, *at).is_ok_and(|size| HOST_INFO_SIZES.contains(&usize::from(size)))
        })
}

fn stub_length(mapped: &[u8], stub: usize) -> usize {
    let after_code = stub.saturating_add(STUB_CODE);
    STUB_MARKERS
        .iter()
        .find(|marker| {
            mapped
                .get(after_code..)
                .is_some_and(|tail| tail.starts_with(marker))
        })
        .map_or(STUB_CODE, |marker| STUB_CODE + marker.len())
}

fn decompress_lzma(stream: &[u8], size: usize) -> Option<Vec<u8>> {
    let field = |offset: usize| Some(read_u32(stream, offset).ok()? as usize);
    let (properties, start) = if field(0)? != size && field(LEGACY_LZMA_SIZE)? == size {
        let [position, literal_position, literal_context] =
            *stream.get(LEGACY_LZMA_PROPERTIES..LEGACY_LZMA_STREAM)?
        else {
            return None;
        };
        let properties = lzma::Properties {
            literal_context,
            literal_position,
            position,
        };
        (properties, LEGACY_LZMA_STREAM)
    } else {
        (field(0)? == size).then_some(())?;
        let properties = lzma::Properties::from_packed(*stream.get(LZMA_PROPERTIES)?).ok()?;
        let sized = stream.get(LZMA_STREAM..LZMA_STREAM + LZMA_SIZE_FIELD)
            == Some((size as u64).to_le_bytes().as_slice());
        (
            properties,
            LZMA_STREAM + usize::from(sized) * LZMA_SIZE_FIELD,
        )
    };

    lzma::decompress(stream.get(start..)?, &properties, size).ok()
}

fn restore_relocations(
    restored: &mut [u8],
    model: &PeModel,
    packed: &PackedImage,
    original: &[u8],
) -> Restoration {
    let start = packed
        .host_field(HOST_RELOCATIONS)
        .filter(|start| *start != 0);
    let Some(start) = start else {
        model.clear_directory(restored, BASERELOC_DIRECTORY);
        return match model.dynamic_base(restored) {
            true => Restoration::Lost, // stripped from exes by default
            false => Restoration::Absent,
        };
    };

    let written = standard_relocations(original, start).and_then(|table| {
        let end = start.checked_add(table.len())?;
        restored.get_mut(start..end)?.copy_from_slice(&table);
        model.set_directory(restored, BASERELOC_DIRECTORY, start, table.len())?;
        Some(Restoration::Restored)
    });

    restored_or_cleared(restored, model, BASERELOC_DIRECTORY, written)
}

fn restore_moved_tls(
    restored: &mut [u8],
    model: &PeModel,
    base: usize,
    end: usize,
    linker_place: Option<usize>,
    report: &mut PackerReport,
) {
    let linker_place = linker_place.or_else(|| tls_before_handlers(restored, model, base));
    let tls = restore_tls(restored, model, base, end, linker_place);
    let placed = matches!(tls, Restoration::Restored | Restoration::Inferred(_));
    report.record(Part::Tls, tls);

    if placed && tls_points_past(restored, model, base, end) {
        report.lost(Part::TlsPointers); // the copy describes the stub's template, index and callbacks
    }
}

fn tls_before_handlers(restored: &[u8], model: &PeModel, base: usize) -> Option<usize> {
    let table = read_u32(restored, safeseh_field(restored, model)?).ok()? as usize;
    table.checked_sub(base)?.checked_sub(TLS_DIRECTORY_PE32) // msvc links .rdata$T right before .rdata$sxdata
}

fn tls_points_past(restored: &[u8], model: &PeModel, base: usize, end: usize) -> bool {
    model
        .directory(restored, TLS_DIRECTORY)
        .and_then(|tls| read_u32(restored, tls.rva().as_usize()).ok())
        .and_then(|template| (template as usize).checked_sub(base))
        .is_some_and(|template| template >= end)
}

fn merged_relocations(table: &[u8], missing: &[(u32, u16)]) -> Option<Vec<u8>> {
    let page_of = |rva: u32| rva & !u32::from(RELOCATION_OFFSET_MASK);
    let mut merged = Vec::with_capacity(table.len() + missing.len() * 2);
    let mut placed = 0;
    let mut at = 0;

    while at < table.len() {
        let (page, size) = relocation_block(table, at)?;
        let words = table.get(at.checked_add(RELOCATION_BLOCK_HEADER)?..at.checked_add(size)?)?;
        let page = u32::try_from(page).ok()?;
        let stripped = missing.iter().filter(|(rva, _)| page_of(*rva) == page);

        let block = table.get(at..at.checked_add(size)?)?;

        if stripped.clone().next().is_none() {
            merged.extend_from_slice(block);
        } else {
            let mut entries = relocation_words(words)
                .filter(|word| *word != 0)
                .map(|word| {
                    let offset = u32::from(word & RELOCATION_OFFSET_MASK);
                    Some((page.checked_add(offset)?, word >> RELOCATION_KIND_SHIFT))
                })
                .collect::<Option<Vec<_>>>()?;
            entries.is_sorted().then_some(())?;

            placed += stripped.clone().count();
            entries.extend(stripped);
            merged.extend(relocation_blocks(&entries)?);
        }

        at = at.checked_add(size)?;
    }

    (placed == missing.len()).then_some(merged)
}

fn cover_stripped_pointers(restored: &mut [u8], model: &PeModel) -> Option<bool> {
    let tls = model.directory(restored, TLS_DIRECTORY);
    let Some(table) = model.directory(restored, BASERELOC_DIRECTORY) else {
        return Some(false);
    };

    let tls_fields = tls.into_iter().flat_map(|tls| {
        (0..TLS_POINTER_FIELDS)
            .map(move |field| tls.rva().as_usize().saturating_add(field * THUNK_SIZE))
    });
    let fields = tls_fields
        .chain(safeseh_field(restored, model))
        .collect::<Vec<_>>();

    let covered = relocated_fields(restored, model)?;
    let missing = fields
        .into_iter()
        .filter(|field| !covered.iter().any(|(at, _)| at == field))
        .filter(|field| read_u32(restored, *field).is_ok_and(|value| value != 0))
        .map(|field| Some((u32::try_from(field).ok()?, RELOCATION_HIGHLOW)))
        .collect::<Option<Vec<_>>>()?;
    if missing.is_empty() {
        return Some(false);
    }

    let start = table.rva().as_usize();
    let size = table.size() as usize;
    let end = start.checked_add(size)?;

    let merged = merged_relocations(restored.get(start..end)?, &missing).filter(|merged| {
        let stop = start.saturating_add(merged.len());
        restored
            .get(end.min(stop)..stop)
            .is_some_and(|grown| grown.iter().all(|byte| *byte == 0))
    });
    if let Some(merged) = merged {
        let stop = start.checked_add(merged.len())?;
        restored.get_mut(start..stop)?.copy_from_slice(&merged);
        restored.get_mut(stop..end.max(stop))?.fill(0);
        model.set_directory(restored, BASERELOC_DIRECTORY, start, merged.len())?;
        return Some(true);
    }

    let blocks = relocation_blocks(&missing)?;
    place(restored, end, &blocks)?;
    let grown = size.checked_add(blocks.len())?;
    model.set_directory(restored, BASERELOC_DIRECTORY, start, grown)?;
    Some(true)
}

fn standard_relocations(bytes: &[u8], start: usize) -> Option<Vec<u8>> {
    let mut table = Vec::new();
    let mut at = start;

    loop {
        let (page, size) = relocation_block(bytes, at)?;
        if page == 0 || size < RELOCATION_BLOCK_HEADER {
            break;
        }

        (size <= MAX_RELOCATION_BLOCK).then_some(())?;
        let words = bytes.get(at.checked_add(RELOCATION_BLOCK_HEADER)?..at.checked_add(size)?)?;
        table.extend_from_slice(bytes.get(at..at.checked_add(RELOCATION_BLOCK_HEADER)?)?);

        let mut entries = relocation_words(words);
        if let Some(first) = entries.next() {
            let kind = first & !RELOCATION_OFFSET_MASK;
            let mut offset = u32::from(first & RELOCATION_OFFSET_MASK);
            let mut padded = false;
            table.extend_from_slice(&first.to_le_bytes());

            for delta in entries {
                (!padded || delta == 0).then_some(())?; // another kind would read as padding too

                offset = offset.checked_add(u32::from(delta))?; // later entries store the distance
                let entry = match u16::try_from(offset) {
                    Ok(offset) if offset <= RELOCATION_OFFSET_MASK => kind | offset,
                    _ => {
                        padded = true; // padding entry runs past the page
                        0
                    }
                };
                table.extend_from_slice(&entry.to_le_bytes());
            }
        }

        at = at.checked_add(size)?;
    }

    (!table.is_empty()).then_some(table)
}

fn restore_exports(restored: &mut [u8], model: &PeModel, end: usize) -> Restoration {
    let Some(directory) = model.directory(restored, EXPORT_DIRECTORY) else {
        return Restoration::Absent;
    };

    let (copy, size) = (directory.rva().as_usize(), directory.size() as usize);
    if copy < end {
        return Restoration::Absent;
    }

    let forwarders = export_forwarders(restored, copy, |rva| {
        (copy..copy.saturating_add(size)).contains(&rva)
    });

    let rebuilt = linker_export_start(restored, copy).and_then(|start| {
        let (_, block) = linker_export_layout(restored, copy, &forwarders, Some(start))?;
        (start.checked_add(block.len())? <= end).then_some(())?;
        place(restored, start, &block)?;
        model.set_directory(restored, EXPORT_DIRECTORY, start, block.len())
    });

    match rebuilt {
        Some(()) => Restoration::Inferred("put back where the linker's layout has it"),
        None => Restoration::Failed,
    }
}

fn directory_moved(restored: &[u8], model: &PeModel, index: usize, end: usize) -> bool {
    model
        .directory(restored, index)
        .is_some_and(|directory| directory.rva().as_usize() >= end)
}

pub(super) struct Pecompact;

impl Packer for Pecompact {
    fn unpack(&self, image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
        unpack(image, origin)
    }

    fn original_code(&self, image: &PeImage<'_>, base: usize) -> Option<Vec<Range<usize>>> {
        original_code(image, base)
    }
}
