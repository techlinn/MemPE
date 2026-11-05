use std::collections::HashSet;
use std::ops::Range;
use std::sync::Arc;

use super::codecs::bitstream::{ByteTags, WordTags};
use super::codecs::{aplib, brieflz, ffce, jcalg1, lzma};
use super::tables::{
    HINT_SIZE, IMPORT_DESCRIPTOR_SIZE, IMPORT_IAT_OFFSET, IMPORT_NAME_OFFSET,
    MAX_IMPORT_DESCRIPTORS, MAX_RELOCATION_BLOCK, MAX_THUNKS, RELOCATION_BLOCK_HEADER,
    RELOCATION_BLOCK_SIZE_OFFSET, Restoration, SectionHints, SectionPiece, THUNK_SIZE,
    apply_listed_imports, clear_directory, export_functions, first_section_range, fresh_image,
    iat_filled, linker_export_layout, linker_export_start, listed_imports, lowest_moved_leaf,
    map_disk_image, name_sections, place, pogo_parts, pogo_sections, pogo_tls_directory,
    read_c_string, relocate, relocated_fields, relocation_blocks, replace_first_section,
    resource_layout, restore_moved_resources, restore_tls, set_directory,
};
use super::{
    ImportedFunction, ModuleImports, Origin, PackerFindings, PackerImports, PackerReport, Unpacked,
    find_pattern,
};
use crate::pe::image::{read_u16, read_u32, write_u32};
use crate::pe::parse::{parse_disk_image, parse_memory_image};
use crate::pe::{
    BASERELOC_DIRECTORY, BOUND_IMPORT_DIRECTORY, DYNAMIC_BASE, EXPORT_DIRECTORY, PeImage, PeKind,
    PeModel, RELOCATION_HIGHLOW, Rva, TLS_DIRECTORY,
};

const NAME: &str = "PECompact";
const SIGNATURE: &[u8] = b"PEC2"; // where the first section header keeps its relocation pointer
const SIGNATURE_OFFSET: usize = 0x18;
const BUILD_OFFSET: usize = 0x1C;
const HANDLER_BODY: &str = "8B 54 24 04 8B 52 0C C6 02 E9 83 C2 05 2B CA 89 4A FC 33 C0 C3"; // turns the faulting instruction into a jump to the loader
const HANDLER_PREFIX: usize = 0x0E; // mov eax, lea ecx and mov [ecx+1], eax come before the body
const PACKER_SECTIONS: usize = 2; // the loader lives in the last section, or the one before a new .reloc
const STUB_CODE: usize = 0x18;
const STUB_REBASED: usize = 5; // mov eax, handler is fixed up by the loader
const STUB_MARKERS: [&[u8]; 2] = [b"PECompact2\0", b"PEC2\0"];
const LOADER_INFO_SIZE: usize = 0x24; // the loader's parameters sit right before the handler
const LOADER_PACKED: usize = 0x00;
const LOADER_SIZE: usize = 0x04;
const LOADER_ENTRY: usize = 0x08;
const LOADER_DECODER: usize = 0x0C;
const HOST_INFO_SIZES: Range<usize> = 0x50..0x100;
const HOST_IMAGE_BASE: usize = 0x04;
const HOST_ENTRY: usize = 0x0C;
const HOST_DECODERS: usize = 0x30; // how far the decoder table sits before the host info
const HOST_IMPORTS: usize = 0x34;
const HOST_OVERFLOWS: usize = 0x4C; // how far the overflow chunks sit before the host info
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
const BLOCK_OVERFLOW: usize = 0x14; // packed bytes that did not fit the section, kept elsewhere
const BLOCK_OVERFLOW_INDEX: usize = 0x18;
const BLOCK_DECODER: usize = 0x1A;
const MAX_BLOCKS: usize = 1_024;
const MERGED: u16 = 0x0002; // a section the packer appended to the first one
const FILTERED: u16 = 0x0008; // calls and jumps rewritten to absolute targets
const ENCODED: u16 = 0x0010;
const MARKED: u16 = 0x0200; // natural call bytes that looked like filter marks
const MAX_MARKS: usize = 1 << 20;
const CALL: u8 = 0xE8;
const JUMP: u8 = 0xE9;
const CALL_SIZE: usize = 5;
const LZMA_PROBABILITY_INIT: &str = "00 03 00 00"; // every lzma decoder starts its probabilities at 0x300
const FFCE_FAR_MATCH: &str = "3D 01 80 00 00"; // cmp eax, 8001h
const APLIB_FAR_MATCH: &str = "3D 00 7D 00 00"; // cmp eax, 7D00h
const BYTE_TAG_REFILL: &str = "02 D2"; // add dl, dl
const COPY_DWORDS: &str = "C1 E9 02 83 E0 03 F3 A5"; // shr ecx, 2 / and eax, 3 / rep movsd
const SWAP_BYTES: &str = "C1 E3 10 81 E2 00 FF 00 00"; // shl ebx, 16 / and edx, 0FF00h
const CRC32_POLYNOMIAL: &str = "35 20 83 B8 ED"; // xor eax, 0EDB88320h
const ELF_HASH_MASK: &str = "25 00 00 00 F0"; // and eax, 0F0000000h
const MAX_DECODERS: usize = 16;
const STORED_HEADER: usize = 4; // copy, invert and checksum streams start with a length
const CHECKSUM_SIZE: usize = 4;
const LZMA_PROPERTIES: usize = 4; // after the unpacked size
const LZMA_STREAM: usize = 9; // properties byte and dictionary size
const LZMA_SIZE_FIELD: usize = 8;
const LEGACY_LZMA_SIZE: usize = 4; // 2.3 writes the probability size first
const LEGACY_LZMA_PROPERTIES: usize = 12; // then pb, lp and lc after the packed size
const LEGACY_LZMA_STREAM: usize = 15;
const RELOCATION_KIND_MASK: u16 = 0xF000;
const RELOCATION_OFFSET_MASK: u16 = 0x0FFF;
const TLS_POINTER_FIELDS: usize = 4; // raw data start and end, index and callback list
const NAME_WINDOW: usize = 0x10000; // the linker puts hint and name strings right around the dll names

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

struct PackedFile {
    mapped: Vec<u8>,
    base: usize,
    loader: Vec<u8>,
    host: usize,
    blocks: Vec<Block>,
    stored: Vec<Range<usize>>,
    original_end: usize,
    in_memory: bool, // read from the running image because the file was not there
}

pub(super) fn unpack(image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
    let model = image.model();
    let header = model.sections().first()?.header_offset;
    let tagged = image
        .bytes()
        .get(header + SIGNATURE_OFFSET..)?
        .starts_with(SIGNATURE);
    (tagged || find_handler(image.bytes(), model).is_some()).then_some(())?; // the tag is easy to wipe, the handler has to stay

    let build = match tagged {
        true => read_u32(image.bytes(), header + BUILD_OFFSET).unwrap_or(0),
        false => 0,
    };
    let version = (build != 0).then(|| format!("build {build}"));
    let packed = origin
        .read_file()
        .and_then(|file| PackedFile::open(&file, image))
        .or_else(|| PackedFile::from_memory(image)); // the packer section stays mapped, loader included
    let Some(packed) = packed else {
        return Some(Unpacked::detected_only(
            NAME,
            version,
            "image (its loader tables could not be read)",
        ));
    };

    restore(image, origin, &packed, version.clone()).or_else(|| {
        Some(Unpacked::detected_only(
            NAME,
            version,
            "image (the loader tables did not fit it)",
        ))
    })
}

fn restore(
    image: &PeImage<'_>,
    origin: &Origin<'_>,
    packed: &PackedFile,
    version: Option<String>,
) -> Option<Unpacked> {
    let model = image.model();
    let end = packed.original_end;
    let mut restored = image.bytes().to_vec();
    let original = packed.original_image();

    let entry = packed.host_field(HOST_ENTRY)?;
    (entry < end).then_some(())?;

    let stub = packed.host_field(HOST_STUB)?;
    let stub_code = stub.checked_add(STUB_REBASED)?..stub.checked_add(STUB_CODE)?;
    let unpacked = match packed.in_memory {
        true => original.is_none(), // the packed data only decodes until the loader unpacks over it
        false => restored.get(stub_code.clone()) != packed.mapped.get(stub_code), // the loader writes over the stub last
    };

    let image_start = model.sections().first()?.virtual_address().as_usize();
    let from_packed = match (unpacked, &original) {
        (true, _) => false,
        (false, Some(original)) => {
            restored
                .get_mut(image_start..end)?
                .copy_from_slice(original.get(image_start..end)?);
            true
        }
        (false, None) => {
            return Some(Unpacked::detected_only(
                NAME,
                version,
                "image (the stub had not finished unpacking)",
            ));
        }
    };

    let mut report = PackerReport::new(NAME, version);
    if from_packed {
        report.restored.push(match packed.in_memory {
            true => "code and data from the packed sections",
            false => "code and data from the packed file",
        }); // dumped before the stub ran
    }

    write_u32(
        &mut restored,
        model.entry_point_offset,
        u32::try_from(entry).ok()?,
    )
    .ok()?;
    report.restored.push("entry point");

    let import_list = packed.host_field(HOST_IMPORTS);
    let modules = match original.as_deref() {
        Some(original) => import_list.and_then(|start| {
            let modules = listed_imports(start, &mut &original[..])?;
            (from_packed || iat_filled(&restored, &modules)).then_some(modules)
        }),
        None => import_list.and_then(|start| imports_left_in_memory(&restored, start)),
    };

    let imports = modules.and_then(|modules| apply_listed_imports(&mut restored, model, modules));
    match imports {
        Some(_) => report.restored.push("imports"),
        None => report.unrestored.push("imports"),
    }

    let relocations = restore_relocations(
        &mut restored,
        model,
        packed,
        original.as_deref().unwrap_or(image.bytes()), // the loader reads its delta list in place and leaves it
    );
    report.record("relocations", relocations);

    if from_packed {
        let delta = origin.base.wrapping_sub(packed.base);
        let mut moved = restored.clone();
        relocate(&mut moved, &restored, model, |value, _| {
            value.wrapping_add(delta)
        });
        restored
            .get_mut(image_start..end)?
            .copy_from_slice(moved.get(image_start..end)?); // only the file's bytes hold values for its own base
    }

    let pogo = pogo_parts(&restored, model, end);
    let merged = packed.original_sections(&restored, model, entry);
    let linker_pieces = merged.as_ref().and(pogo.as_deref()).and_then(|parts| {
        pogo_sections(parts, model, first_section_range(model)?.end, Some(entry))
    }); // only where the packer merged sections
    let from_linker = linker_pieces.is_some();
    let sections = linker_pieces.or(merged);

    let ranges = match &sections {
        Some(sections) => sections
            .iter()
            .map(|piece| piece.start..piece.end)
            .collect(),
        None => packed.stored.clone(), // without merging the packer keeps the section table
    };

    let layout = resource_layout(&restored, model, std::iter::empty());
    let resources = restore_moved_resources(&mut restored, model, &ranges, end, layout, None);
    report.record("resources", resources);

    let exports = restore_exports(&mut restored, model, end);
    report.record("exports", exports);

    if directory_moved(&restored, model, TLS_DIRECTORY, end) {
        let tls = restore_tls(
            &mut restored,
            model,
            origin.base,
            end,
            pogo.as_deref().and_then(pogo_tls_directory),
        ); // the packer wipes the original and its fixups
        report.record("original TLS directory", tls);
    }

    let _ = cover_tls_directory(&mut restored, model);

    match (sections, from_linker) {
        (Some(sections), true)
            if replace_first_section(&mut restored, model, &sections).is_some() =>
        {
            report.restored.push("section table");
        }
        (Some(sections), _) => {
            if replace_first_section(&mut restored, model, &sections).is_some() {
                report.restored.push("code and data sections");
            }
            report.lost.push("section table");
        }
        (None, _) => report.lost.push("section flags"), // the packer makes every section writable
    }

    clear_directory(&mut restored, model, BOUND_IMPORT_DIRECTORY);
    parse_memory_image(&restored).ok()?;

    let fresh = original.filter(|_| !from_packed).and_then(|original| {
        fresh_image(
            image.bytes(),
            &restored,
            &original,
            packed.base,
            origin.base,
            end,
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

impl PackedFile {
    fn open(file: &[u8], image: &PeImage<'_>) -> Option<Self> {
        let disk = parse_disk_image(file).ok()?;
        let model = disk.model();
        let memory = image.model();
        let entry = read_u32(file, model.entry_point_offset).ok()? as usize;
        let same_image = model.image_size == memory.image_size
            && read_u32(image.bytes(), memory.entry_point_offset).ok()? as usize == entry;
        same_image.then_some(())?; // the file on disk must be the one that is running

        let mapped = map_disk_image(file, model.image_size as usize)?;
        let packed = Self::load(mapped, model, memory, false)?;
        let base = read_u32(file, model.image_base_offset).ok()? as usize;
        (packed.base == base).then_some(packed)
    }

    fn from_memory(image: &PeImage<'_>) -> Option<Self> {
        Self::load(image.bytes().to_vec(), image.model(), image.model(), true)
    }

    fn load(mapped: Vec<u8>, layout: &PeModel, memory: &PeModel, in_memory: bool) -> Option<Self> {
        (layout.kind() == PeKind::Pe32).then_some(())?;
        let handler = find_handler(&mapped, layout)?; // found by its body, entry stubs vary
        let info = handler.checked_sub(LOADER_INFO_SIZE)?;
        let field = |offset: usize| Some(read_u32(&mapped, info + offset).ok()? as usize);
        let packed_loader = mapped.get(field(LOADER_PACKED)?..)?;
        let decoder = mapped.get(field(LOADER_DECODER)?..info)?;
        let loader_size = field(LOADER_SIZE).filter(|size| *size <= mapped.len())?; // sizes come from the file, so cap them by the image
        let loader = Codec::identify(decoder, packed_loader).decode(packed_loader, loader_size)?;
        let host = host_info(&loader, field(LOADER_ENTRY)?)?;

        let handler_rva = Rva(u32::try_from(handler).ok()?);
        let original_end = memory
            .sections()
            .iter()
            .find(|section| section.contains_rva(handler_rva))?
            .virtual_address()
            .as_usize(); // the packer's own sections follow the original image

        let stored = layout
            .sections()
            .iter()
            .map(|section| {
                let start = section.virtual_address().as_usize();
                start..start.saturating_add(section.span() as usize)
            })
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
                let offset = read_u32(&self.loader, table + index * 4).ok()? as usize;
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
                Codec::Checksum => unwrap_checksum(&data)?,
                codec if position == 0 => codec.decode(&data, block.original_length)?,
                _ => return None, // only checksums are chained after the compressor
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
            .copy_from_slice(covered); // the entry stub was written over packed data

        let flagged = |flag: u16| {
            self.blocks
                .iter()
                .filter(move |block| block.flags & flag != 0)
        };
        let mut merged = vec![0u8; packed.len()];
        for block in flagged(ENCODED) {
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

        for block in flagged(FILTERED) {
            unfilter(
                merged.get_mut(block.source..block.source.checked_add(block.length)?)?,
                block.extra,
            );
        }

        for block in flagged(MARKED) {
            for index in 0..MAX_MARKS {
                let rva = read_u32(&self.mapped, block.source + index * 4).ok()? as usize;
                if rva == 0 {
                    break;
                }

                merged
                    .get_mut(rva..rva.checked_add(2)?)?
                    .copy_from_slice(&block.extra.to_le_bytes());
            }
        }

        let mut image = vec![0u8; packed.len()];
        let overlaps = |range: &Range<usize>, start: usize, length: usize| {
            start < range.end && range.start < start.saturating_add(length)
        };
        for range in &self.stored {
            let packed_here = flagged(ENCODED)
                .any(|block| overlaps(range, block.destination, block.original_length))
                || flagged(MERGED).any(|block| overlaps(range, block.source, block.length));
            if !packed_here {
                image
                    .get_mut(range.clone())?
                    .copy_from_slice(packed.get(range.clone())?); // kept uncompressed
            }
        }

        for block in flagged(ENCODED) {
            let decoded_end = block.destination.checked_add(block.original_length)?;
            let kept_end = flagged(MERGED)
                .map(|moved| moved.destination)
                .filter(|start| (block.destination..decoded_end).contains(start))
                .min()
                .unwrap_or(decoded_end); // everything after this was moved back out
            image
                .get_mut(block.destination..kept_end)?
                .copy_from_slice(merged.get(block.destination..kept_end)?);
        }

        for block in flagged(MERGED) {
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
    ) -> Option<Vec<SectionPiece>> {
        self.blocks
            .iter()
            .any(|block| block.flags & MERGED != 0)
            .then_some(())?;

        let packed_end = first_section_range(model)?.end;

        let first = self
            .blocks
            .iter()
            .filter(|block| block.flags & ENCODED != 0)
            .map(|block| block.destination)
            .min();
        let starts = self
            .blocks
            .iter()
            .filter(|block| block.flags & MERGED != 0)
            .map(|block| block.source)
            .chain(first)
            .filter(|start| *start < packed_end)
            .collect::<Vec<_>>();

        let relocations = self.host_field(HOST_RELOCATIONS);
        let resources = lowest_moved_leaf(restored, model, self.original_end);
        let hints = SectionHints {
            code: Some(entry),
            code_end: None,
            constants: None,
            relocations,
            resources,
        };
        Some(name_sections(starts, packed_end, &hints))
    }
}

impl Codec {
    fn identify(decoder: &[u8], stream: &[u8]) -> Self {
        let has = |pattern: &str| find_pattern(decoder, pattern).is_some();
        if has(CRC32_POLYNOMIAL) || has(ELF_HASH_MASK) {
            Self::Checksum
        } else if has(COPY_DWORDS) {
            Self::Copy
        } else if has(SWAP_BYTES) {
            Self::Invert
        } else if stream.starts_with(jcalg1::MAGIC) {
            Self::Jcalg1
        } else if has(LZMA_PROBABILITY_INIT) {
            Self::Lzma
        } else if has(FFCE_FAR_MATCH) {
            Self::Ffce
        } else if has(APLIB_FAR_MATCH) {
            Self::Aplib {
                word_tags: !has(BYTE_TAG_REFILL),
            }
        } else {
            Self::BriefLz // its fast decoder carries no constant of its own
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
                output.extend_from_slice(tail); // the last few bytes stay as they are
                output
            }),
            Self::Ffce => ffce::decompress(stream, size),
            Self::Aplib { word_tags: true } => {
                aplib::decompress(WordTags::new(stream, 0), size, aplib::Variant::Classic)
            }
            Self::Aplib { word_tags: false } => {
                aplib::decompress(ByteTags::new(stream), size, aplib::Variant::Classic)
            }
            Self::BriefLz => brieflz::decompress(stream, size),
            Self::Jcalg1 => jcalg1::decompress(stream, size),
            Self::Lzma => decompress_lzma(stream, size),
        }?;

        (decoded.len() == size).then_some(decoded)
    }
}

fn find_handler(bytes: &[u8], model: &PeModel) -> Option<usize> {
    let sections = model.sections();
    sections
        .iter()
        .skip(sections.len().saturating_sub(PACKER_SECTIONS))
        .find_map(|section| {
            let start = section.virtual_address().as_usize();
            let end = start
                .saturating_add(section.span() as usize)
                .min(bytes.len());
            let body = find_pattern(bytes.get(start..end)?, HANDLER_BODY)?;
            (start + body).checked_sub(HANDLER_PREFIX)
        })
}

fn imports_left_in_memory(memory: &[u8], start: usize) -> Option<Vec<ModuleImports>> {
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
        let slots = (0..MAX_THUNKS)
            .take_while(|slot| {
                read_u32(memory, iat.saturating_add(slot * THUNK_SIZE))
                    .is_ok_and(|value| value != 0)
            })
            .count(); // the loader filled every slot with its address
        found.push((name, module, iat, slots));
    }

    let listed = Arc::new(leftover_names(
        memory,
        found.iter().map(|(name, ..)| *name),
    )?);
    let modules = found
        .into_iter()
        .map(|(_, module, iat, slots)| {
            Some(ModuleImports {
                module,
                first_thunk: u32::try_from(iat).ok()?,
                functions: vec![ImportedFunction::NameFromAddressAmong(Arc::clone(&listed)); slots],
            })
        })
        .collect::<Option<Vec<_>>>()?;
    (!modules.is_empty()).then_some(modules)
}

fn leftover_names(
    memory: &[u8],
    module_names: impl Iterator<Item = usize>,
) -> Option<HashSet<String>> {
    let (low, high) = module_names.fold((usize::MAX, 0), |(low, high), at| {
        (low.min(at), high.max(at))
    });
    let window = memory
        .get(low.saturating_sub(NAME_WINDOW)..high.saturating_add(NAME_WINDOW).min(memory.len()))?;
    let identifier =
        |byte: &u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'@' | b'?' | b'$');

    let names = window
        .split(|byte| !identifier(byte))
        .filter(|run| run.len() > HINT_SIZE)
        .flat_map(|run| (0..=HINT_SIZE).map(move |skip| &run[skip..])) // a hint can read as letters too
        .filter_map(|run| std::str::from_utf8(run).ok())
        .map(str::to_owned)
        .collect::<HashSet<_>>();
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
    let distance = read_u32(loader, entry.checked_sub(4)?).ok()? as usize; // stored right before the loader's entry
    let start = entry.checked_sub(distance)?;
    [Some(start), start.checked_sub(4)]
        .into_iter()
        .flatten()
        .find(|at| {
            read_u16(loader, *at).is_ok_and(|size| HOST_INFO_SIZES.contains(&usize::from(size)))
        })
}

fn stub_length(mapped: &[u8], stub: usize) -> usize {
    let after_code = stub + STUB_CODE;
    STUB_MARKERS
        .iter()
        .find(|marker| {
            mapped
                .get(after_code..)
                .is_some_and(|tail| tail.starts_with(marker))
        })
        .map_or(STUB_CODE, |marker| STUB_CODE + marker.len())
}

fn unfilter(code: &mut [u8], marks: u16) {
    let [call_mark, jump_mark] = marks.to_le_bytes();
    let mut at = 0;

    while at + CALL_SIZE <= code.len() {
        let marked = matches!(
            (code[at], code[at + 1]),
            (CALL, mark) if mark == call_mark
        ) || matches!((code[at], code[at + 1]), (JUMP, mark) if mark == jump_mark);
        if !marked {
            at += 1;
            continue;
        }

        let target = u32::from_be_bytes([0, code[at + 2], code[at + 3], code[at + 4]]); // stored as a 24 bit position
        let Ok(position) = u32::try_from(at) else {
            return;
        };
        let relative = target.wrapping_sub(position);
        code[at + 1..at + CALL_SIZE].copy_from_slice(&relative.to_le_bytes());
        at += CALL_SIZE;
    }
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
        let properties = lzma::Properties::from_packed(*stream.get(LZMA_PROPERTIES)?)?;
        let sized = stream.get(LZMA_STREAM..LZMA_STREAM + LZMA_SIZE_FIELD)
            == Some((size as u64).to_le_bytes().as_slice());
        (
            properties,
            LZMA_STREAM + usize::from(sized) * LZMA_SIZE_FIELD,
        )
    };

    lzma::decompress(stream.get(start..)?, &properties, size)
}

fn restore_relocations(
    restored: &mut [u8],
    model: &PeModel,
    packed: &PackedFile,
    original: &[u8],
) -> Restoration {
    let packer_table = model
        .directory(restored, BASERELOC_DIRECTORY)
        .ok()
        .flatten()
        .map(|directory| directory.rva().as_usize());

    let start = packed
        .host_field(HOST_RELOCATIONS)
        .filter(|start| *start != 0);
    let original_table = start.and_then(|start| standard_relocations(original, start));
    let state = match (start, &original_table) {
        (Some(_), Some(_)) => Restoration::Restored,
        (Some(_), None) => Restoration::Failed,
        (None, _) if dynamic_base(restored, model) => Restoration::Lost, // stripped from exes by default
        (None, _) => Restoration::Absent,
    };

    let location = match original_table {
        Some(_) => start,
        None => packer_table,
    };
    let table = original_table.unwrap_or_default();

    let written = location.filter(|_| !table.is_empty()).and_then(|start| {
        let end = start.checked_add(table.len())?;
        restored.get_mut(start..end)?.copy_from_slice(&table);
        set_directory(restored, model, BASERELOC_DIRECTORY, start, table.len())
    });
    if written.is_none() {
        clear_directory(restored, model, BASERELOC_DIRECTORY);
    }

    state
}

fn cover_tls_directory(restored: &mut [u8], model: &PeModel) -> Option<()> {
    let tls = model
        .directory(restored, TLS_DIRECTORY)
        .ok()??
        .rva()
        .as_usize();

    let table = model.directory(restored, BASERELOC_DIRECTORY).ok()??;
    let covered = relocated_fields(restored, model)?;
    let missing = (0..TLS_POINTER_FIELDS)
        .map(|field| tls.checked_add(field * THUNK_SIZE))
        .collect::<Option<Vec<_>>>()?
        .into_iter()
        .filter(|field| !covered.iter().any(|(at, _)| at == field))
        .filter(|field| read_u32(restored, *field).is_ok_and(|value| value != 0)) // zero fields stay zero
        .map(|field| Some((u32::try_from(field).ok()?, RELOCATION_HIGHLOW)))
        .collect::<Option<Vec<_>>>()?;
    if missing.is_empty() {
        return Some(());
    }

    let blocks = relocation_blocks(&missing)?;
    let start = table.rva().as_usize();
    let end = start.checked_add(table.size() as usize)?;

    place(restored, end, &blocks)?;
    set_directory(
        restored,
        model,
        BASERELOC_DIRECTORY,
        start,
        table.size() as usize + blocks.len(),
    )
}

fn dynamic_base(restored: &[u8], model: &PeModel) -> bool {
    read_u16(restored, model.dll_characteristics_offset)
        .is_ok_and(|flags| flags & DYNAMIC_BASE != 0)
}

fn standard_relocations(bytes: &[u8], start: usize) -> Option<Vec<u8>> {
    let mut table = Vec::new();
    let mut at = start;

    loop {
        let page = read_u32(bytes, at).ok()?;
        let size = read_u32(bytes, at.checked_add(RELOCATION_BLOCK_SIZE_OFFSET)?).ok()? as usize;
        if page == 0 || size < RELOCATION_BLOCK_HEADER {
            break;
        }

        (size <= MAX_RELOCATION_BLOCK).then_some(())?;
        let words = bytes.get(at.checked_add(RELOCATION_BLOCK_HEADER)?..at.checked_add(size)?)?;
        table.extend_from_slice(bytes.get(at..at + RELOCATION_BLOCK_HEADER)?);

        let mut entries = words
            .as_chunks::<2>()
            .0
            .iter()
            .map(|word| u16::from_le_bytes(*word));
        if let Some(first) = entries.next() {
            let kind = first & RELOCATION_KIND_MASK;
            let mut offset = u32::from(first & RELOCATION_OFFSET_MASK);
            table.extend_from_slice(&first.to_le_bytes());

            for delta in entries {
                offset = offset.checked_add(u32::from(delta))?; // later entries only store the distance
                let entry = match u16::try_from(offset) {
                    Ok(offset) if offset <= RELOCATION_OFFSET_MASK => kind | offset,
                    _ => 0, // the padding entry runs past the page
                };
                table.extend_from_slice(&entry.to_le_bytes());
            }
        }

        at = at.checked_add(size)?;
    }

    (!table.is_empty()).then_some(table)
}

fn restore_exports(restored: &mut [u8], model: &PeModel, end: usize) -> Restoration {
    let Ok(Some(directory)) = model.directory(restored, EXPORT_DIRECTORY) else {
        return Restoration::Absent;
    };

    let (copy, size) = (directory.rva().as_usize(), directory.size() as usize);
    if copy < end {
        return Restoration::Absent;
    }

    let forwarders = export_functions(restored, copy)
        .unwrap_or_default()
        .into_iter()
        .filter(|rva| (copy..copy.saturating_add(size)).contains(rva))
        .filter_map(|rva| Some((rva, read_c_string(restored, rva)?.0)))
        .collect::<Vec<_>>();

    let rebuilt = linker_export_start(restored, copy).and_then(|start| {
        let (_, block) = linker_export_layout(restored, copy, &forwarders, Some(start))?;
        (start.checked_add(block.len())? <= end).then_some(())?;
        let target = restored.get_mut(start..start + block.len())?;
        let free = target
            .iter()
            .zip(&block)
            .all(|(old, new)| *old == 0 || old == new); // the packer zeroed the tables but left the strings
        free.then_some(())?;
        target.copy_from_slice(&block);
        set_directory(restored, model, EXPORT_DIRECTORY, start, block.len())
    });

    match rebuilt {
        Some(()) => Restoration::Restored,
        None => Restoration::Failed,
    }
}

fn directory_moved(restored: &[u8], model: &PeModel, index: usize, end: usize) -> bool {
    model
        .directory(restored, index)
        .ok()
        .flatten()
        .is_some_and(|directory| directory.rva().as_usize() >= end)
}
