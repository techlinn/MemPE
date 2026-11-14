mod mutation;

use std::ops::Range;

use super::emu;
use super::tables::{
    CODE_SECTION, DATA_SECTION, RELOCATION_BLOCK_HEADER, SECTION_CHARACTERISTICS_OFFSET,
    SECTION_COUNT_OFFSET, SECTION_RVA_OFFSET, SECTION_VIRTUAL_SIZE_OFFSET,
};
use super::{Origin, PackerFindings, PackerImports, PackerReport, Unpacked, find_patterns};
use crate::pe::image::{read_pointer, read_u16, read_u32, write_u16, write_u32, write_u64};
use crate::pe::{
    BASERELOC_DIRECTORY, DEBUG_DIRECTORY, DELAY_IMPORT_DIRECTORY, EXCEPTION_DIRECTORY,
    EXPORT_DIRECTORY, IAT_DIRECTORY, IMPORT_DIRECTORY, LOAD_CONFIG_DIRECTORY, PeImage, PeKind,
    PeModel, RUNTIME_FUNCTION_SIZE, Rva, SECTION_HEADER_SIZE, SECURITY_DIRECTORY, SectionModel,
    TLS_DIRECTORY,
};

const BSS_SECTION: u32 = 0x4000_0080; // readable uninitialized data
const MAX_IAT_IMAGE: usize = 1 << 30; // keep the grown image within the rebuild 1 GiB ceiling
const MODULE_GAP: u64 = 0x1_0000; // api addresses this far apart get a zero slot between them

const REL_CALL_LEN: usize = 5; // E8/E9 + rel32
const VM_ENTRY_LEN: usize = 10; // push imm32 with the handler key then call into the vm
const PUSH_IMM32: u8 = 0x68;
const CALL_REL32: u8 = 0xE8;

const EXPORT_TABLE_FIELDS: [usize; 4] = [12, 28, 32, 36]; // Name, AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals
const EXPORT_NAME_COUNT: usize = 24;
const EXPORT_NAMES_RVA: usize = 32;
const DELAY_LOOKUP_RVA: usize = 16;
const TLS_POINTER_FIELDS: usize = 4; // raw data start and end, index, callbacks
const DEBUG_ENTRY_SIZE: usize = 28;
const DEBUG_RAW_DATA_RVA: usize = 20;
const DELAY_DESCRIPTOR_SIZE: usize = 32;
const DELAY_RVA_FIELDS: [usize; 5] = [4, 8, 12, 16, 20]; // name, module handle, iat, int, bound iat
const MAX_TABLE_ENTRIES: usize = 4096;
const MAX_STUB_SITES: usize = 200_000;
const PACKED_ENTROPY: f64 = 6.5; // vmp payload sections are near random and the original code sits well below
const ENTROPY_STEP: usize = 4; // sampling every few bytes is enough to tell packed from code

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ImportForm {
    Call,
    Jump,
    Load(u8), // by gpr number
}

pub(super) struct ResolvedImport {
    pub(super) site: usize,
    pub(super) len: usize, // the bytes vmp rewrote from `site`
    pub(super) form: ImportForm,
    pub(super) target: u64,
}

const NAME: &str = "VMProtect";
const MIN_VM_SECTION: u32 = 0x1_0000; // the vm section dwarfs the original ones
const COMPANION_DIRECTORIES: [usize; 4] = [
    EXCEPTION_DIRECTORY,
    TLS_DIRECTORY,
    LOAD_CONFIG_DIRECTORY,
    DELAY_IMPORT_DIRECTORY,
];
const MSVC_ENTRY_X64: &str = "48 83 EC 28 E8 ?? ?? ?? ?? 48 83 C4 28 E9 ?? ?? ?? ??"; // the msvc mainCRTStartup still native under vmp
const MSVC_ENTRY_X86: &str = "CC CC E8 ?? ?? ?? ?? E9 ?? ?? ?? ??"; // __security_init_cookie then a tail jump into __scrt_common_main_seh
const X86_ENTRY_SKIP: usize = 2; // the match starts at the int3 padding before the prologue
const MINGW_CONSOLE_X64: &str =
    "48 83 EC 28 48 8B 05 ?? ?? ?? ?? C7 00 00 00 00 00 E8 ?? ?? ?? ?? 90 90 48 83 C4 28 C3"; // mingw stores __mingw_app_type 0
const MINGW_GUI_X64: &str =
    "48 83 EC 28 48 8B 05 ?? ?? ?? ?? C7 00 01 00 00 00 E8 ?? ?? ?? ?? 90 90 48 83 C4 28 C3"; // the same storing 1 for WinMainCRTStartup
const GO_RT0_X64: &str = "48 8B 3C 24 48 8D 74 24 08 E9"; // the go _rt0_amd64 handing argc/argv on to rt0_go
const GO_RT0_X86: &str = "83 EC 08 8B 44 24 08 8D 5C 24 0C 89 04 24 89 5C 24 04 E9";
const VB6_ENTRY: &str = "68 ?? ?? ?? ?? E8 ?? ?? ?? ??"; // push offset VBHeader then call ThunRTMain
const VB6_HEADER_MAGIC: &[u8; 4] = b"VB5!";
const DELPHI_INIT: &str = "B8 ?? ?? ?? ?? E8"; // mov eax offset InitTable then call @InitExe
const DELPHI_FRAME: &str = "55 8B EC"; // matched apart from the call where the locals between them vary
const DELPHI_FRAME_REACH: usize = 12; // bytes back from the call to the program block frame setup
const MAX_DELPHI_UNITS: u32 = 100_000;
const VC6_ENTRY: &str = concat!(
    "55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 ",
    "83 EC ?? 53 56 57 89 65 E8 33 DB 89 5D FC 6A ?? 5F 57 ?? ?? ?? ?? ?? ?? 59 ",
    "83 0D ?? ?? ?? ?? FF 83 0D ?? ?? ?? ?? FF",
);
const SUBSYSTEM_FROM_IMAGE_SIZE: usize = 12; // optional header Subsystem sits 12 bytes past SizeOfImage
const SUBSYSTEM_GUI: u16 = 2;
const SUBSYSTEM_CONSOLE: u16 = 3;

pub(super) fn unpack(image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
    let model = image.model();
    let vm = vm_section(image.bytes(), model)?;

    let mut report = PackerReport::new(NAME, None);
    let mut restored = image.bytes().to_vec();
    let bits = match model.kind() {
        PeKind::Pe32 => 32,
        PeKind::Pe32Plus => 64,
    };
    let base = origin.base as u64;
    let code = original_code(image.bytes(), model, &vm);
    let payload = payload_start(image.bytes(), model, &vm);

    let returns_to = |site| emu::stub_return(image.bytes(), base, bits, site);
    let imports = |site| place(image.bytes(), origin, bits, site, site).is_ok();
    let vm_code = mutation::Payload {
        range: base + payload as u64..base + image.bytes().len() as u64,
        returns_to: &returns_to,
        imports: &imports,
    };

    let demutated = restore_mutated(image, &mut restored, &code, &vm_code, base, bits);
    if demutated.mutated > 0 {
        report.notes.push(format!(
            "{} of {} mutated functions cleaned into .vmpcode, {} of them verified to behave as vmp's copy did and aimed at from the original code",
            demutated.mutated, demutated.mutated, demutated.written
        ));
    }

    let sites: Vec<Range<usize>> = code.iter().cloned().chain(demutated.code).collect();
    let (resolved, refused) = resolve_imports(&restored, model, &vm, &sites, &vm_code, origin);
    let block = payload..vm.end;
    let confirmed = !resolved.is_empty()
        || demutated.mutated > 0
        || vmp_section_name(model)
        || vm_entry(image.bytes(), model, &block);
    if !confirmed {
        let reason =
            "image (the layout looks like vmp, but nothing confirmed it, so it was left as it is)";
        return Some(Unpacked::detected_only(NAME, None, reason));
    }

    let imports = rebuild_imports(&mut restored, model, &resolved, origin.base);
    match imports {
        Some(_) => report.restored.push("imports"),
        None => report
            .unrestored
            .push("imports (the original table is left as junk)"),
    }

    if refused > 0 {
        report.unrestored.push(
            "some calls into vmp code (virtualized entries, or stubs with no single reading)",
        );
    }
    if !resolved.is_empty() || refused > 0 {
        report.notes.push(format!(
            "{} import call sites rebuilt, {refused} other calls into vmp code left as they are",
            resolved.len()
        ));
    }

    if let Some(dropped) = drop_vm_unwind(&mut restored, model, &code)
        && dropped > 0
    {
        report.notes.push(format!(
            "{dropped} exception-table entries for vmp's own code dropped, so disassemblers skip its junk"
        ));
    }

    match original_entry(&restored, model, &vm, origin.base) {
        Some(oep) => {
            write_u32(
                &mut restored,
                model.entry_point_offset,
                u32::try_from(oep).ok()?,
            )
            .ok()?;
            report.restored.push("original entry point");
        }
        None => report.unrestored.push(
            "original entry point (virtualized, or a hand-written entry with no runtime to recognise)",
        ),
    }

    if !evacuate(&mut restored, model, &(0..payload), &block) {
        report
            .unrestored
            .push("vmp's sections (a table they hold had nowhere to move to)");
    } else {
        let referenced = table_references(&restored, model, origin.base);
        let sections = vmp_sections(model, &block);
        let (pinned, unused): (Vec<_>, Vec<_>) = sections
            .iter()
            .cloned()
            .partition(|section| referenced.iter().any(|rva| section.contains(rva)));
        if !pinned.is_empty() {
            report.unrestored.push(
                "some of vmp's sections (a table moved out of them still points at data they hold)",
            );
        }

        if let Some((dropped, kept)) = drop_vm_relocations(&mut restored, model, &sections) // a kept section's fixups are still vmp's own
            && dropped > 0
        {
            report.notes.push(match kept {
                0 => format!(
                    "{dropped} relocation blocks dropped, every one of them vmp's own pages: it applies the program's fixups itself and tables none, so the dump has no relocations to carry"
                ),
                kept => format!(
                    "{dropped} relocation blocks for vmp's own pages dropped, {kept} of the program's kept"
                ),
            });
        }

        let dropped = shed(&mut restored, model, &unused);
        if dropped > 0 {
            report.notes.push(format!(
                "{} KiB of vmp's own sections dropped from the file, their pages left mapped and empty",
                dropped / 1024
            ));
        }
    }

    report.lost.push(if demutated.written < demutated.mutated {
        "virtualized code, and mutated code that could not be written back"
    } else {
        "virtualized code"
    });

    Some(Unpacked {
        image: Some(restored),
        findings: PackerFindings {
            report,
            imports: imports.unwrap_or(PackerImports::Unknown),
        },
        fresh: None,
    })
}

struct Restored {
    written: usize,             // cleans verified and aimed at from the original code
    mutated: usize,             // functions that cleaned to whole code aimed at or not
    code: Option<Range<usize>>, // where the cleaned code landed for the import scan to cover
}

fn restore_mutated(
    image: &PeImage<'_>,
    restored: &mut Vec<u8>,
    code: &[Range<usize>],
    vm_code: &mutation::Payload<'_>,
    base: u64,
    bits: u32,
) -> Restored {
    let empty = Restored {
        written: 0,
        mutated: 0,
        code: None,
    };

    let model = image.model();
    let Some(at) = next_section_rva(restored, model) else {
        return empty;
    };
    let relocated = mutation::reencode(image.bytes(), base, bits, code, vm_code, base + at as u64);
    if relocated.code.is_empty()
        || append(restored, model, b".vmpcode", CODE_SECTION, &relocated.code).is_none()
    {
        return Restored {
            mutated: relocated.recoverable,
            ..empty
        };
    }

    let mut written = 0;
    for moved in &relocated.moved {
        let jump = moved.site + 1..moved.site + 5;
        let rel = moved.entry as i64 - (base + moved.site as u64 + 5) as i64;
        let Ok(rel) = i32::try_from(rel) else {
            continue;
        };
        let Some(slot) = restored.get_mut(jump.clone()) else {
            continue; // the site came from a five byte branch in the image so this should hold
        };
        let original = slot.to_vec();
        slot.copy_from_slice(&rel.to_le_bytes());

        if emu::same_behaviour(
            image.bytes(),
            restored,
            base,
            bits,
            base + moved.site as u64,
        ) {
            written += 1;
        } else if let Some(slot) = restored.get_mut(jump) {
            slot.copy_from_slice(&original);
        }
    }

    Restored {
        written,
        mutated: relocated.recoverable,
        code: Some(at..at + relocated.code.len()),
    }
}

fn rebuild_imports(
    restored: &mut Vec<u8>,
    model: &PeModel,
    sites: &[ResolvedImport],
    base: usize,
) -> Option<PackerImports> {
    (!sites.is_empty()).then_some(())?;
    let width = model.kind().pointer_width();

    let mut distinct: Vec<u64> = sites.iter().map(|site| site.target).collect();
    distinct.sort_unstable(); // address order groups each module apis so a zero slot can end the run
    distinct.dedup();

    let mut slot_of = std::collections::HashMap::new();
    let mut layout: Vec<Option<u64>> = Vec::new(); // None marks a terminator slot between modules
    let mut previous: Option<u64> = None;
    for target in distinct {
        if previous.is_some_and(|prev| target.saturating_sub(prev) >= MODULE_GAP) {
            layout.push(None);
        }
        slot_of.insert(target, layout.len());
        layout.push(Some(target));
        previous = Some(target);
    }

    let iat_size = layout.len().checked_mul(width)?;
    let iat_rva = append(
        restored,
        model,
        b".vmpiat\0",
        DATA_SECTION,
        &vec![0; iat_size],
    )?;
    for (index, target) in layout.iter().enumerate() {
        let Some(target) = target else { continue };
        let at = iat_rva + index * width;
        match width {
            8 => write_u64(restored, at, *target).ok()?,
            _ => write_u32(restored, at, u32::try_from(*target).ok()?).ok()?,
        }
    }

    for site in sites {
        let slot_rva = iat_rva + slot_of.get(&site.target)? * width;
        let end = site.site.checked_add(site.len)?;
        let disp = match model.kind() {
            PeKind::Pe32Plus => i32::try_from(slot_rva as i64 - end as i64).ok()?, // x64 reads the slot rip relative and x86 absolute
            PeKind::Pe32 => i32::from_ne_bytes(u32::try_from(base + slot_rva).ok()?.to_ne_bytes()),
        };

        let encoded = encode(site.form, site.len, model.kind(), disp);
        (encoded.len() == site.len).then_some(())?;
        restored.get_mut(site.site..end)?.copy_from_slice(&encoded);
    }

    let rva = u32::try_from(iat_rva).ok()?;
    let size = u32::try_from(iat_size).ok()?;

    if let Ok(Some(offset)) = model.directory_offset(IAT_DIRECTORY) {
        write_u32(restored, offset, rva).ok()?;
        write_u32(restored, offset + 4, size).ok()?;
    }

    Some(PackerImports::FilledIat { rva, size }) // the rebuild names each slot from the dumped modules exports
}

fn drop_vm_unwind(restored: &mut [u8], model: &PeModel, code: &[Range<usize>]) -> Option<usize> {
    let entry = model.directory_offset(EXCEPTION_DIRECTORY).ok()??;
    let rva = read_u32(restored, entry).ok()? as usize;
    let size = read_u32(restored, entry + 4).ok()? as usize;
    let table = restored.get(rva..rva.checked_add(size)?)?.to_vec();

    let kept: Vec<u8> = table
        .as_chunks::<RUNTIME_FUNCTION_SIZE>()
        .0
        .iter()
        .filter(|function| {
            let begin = read_u32(function.as_slice(), 0).map_or(0, |begin| begin as usize);
            code.iter().any(|range| range.contains(&begin)) // vmp lists its vm handlers here and disassemblers carve functions from the junk
        })
        .flatten()
        .copied()
        .collect();

    let area = restored.get_mut(rva..rva + size)?;
    area.fill(0);
    area[..kept.len()].copy_from_slice(&kept);
    write_u32(restored, entry + 4, u32::try_from(kept.len()).ok()?).ok()?;
    Some((table.len() - kept.len()) / RUNTIME_FUNCTION_SIZE)
}

fn reclaim(
    restored: &mut [u8],
    model: &PeModel,
    original: &Range<usize>,
    size: usize,
) -> Option<usize> {
    let align = (model.section_alignment as usize).max(1); // a header may claim no alignment at all
    let mut rooms: Vec<&SectionModel> = model
        .sections()
        .iter()
        .filter(|section| original.contains(&section.virtual_address().as_usize()))
        .collect();
    rooms.sort_by_key(|section| section.is_executable());

    for section in rooms {
        let start = section.virtual_address().as_usize();
        let Some(at) = start.checked_add(section.span() as usize) else {
            continue;
        };
        let Some(end) = at.checked_add(size) else {
            continue;
        };
        let next = model
            .sections()
            .iter()
            .map(|other| other.virtual_address().as_usize())
            .filter(|other| *other > start)
            .min()
            .unwrap_or(usize::MAX);
        let ceiling = next.min(at.next_multiple_of(align)).min(restored.len());

        let padding = restored
            .get(at..end)
            .filter(|_| end <= ceiling)
            .is_some_and(|room| room.iter().all(|byte| *byte == 0));
        if !padding {
            continue;
        }

        let Ok(grown) = u32::try_from(end - start) else {
            continue;
        };
        let header = section.header_offset + SECTION_VIRTUAL_SIZE_OFFSET;
        if write_u32(restored, header, grown).is_ok() {
            return Some(at);
        }
    }

    None
}

fn evacuate(
    restored: &mut Vec<u8>,
    model: &PeModel,
    original: &Range<usize>,
    block: &Range<usize>,
) -> bool {
    for directory in 0..model.directory_count {
        if matches!(directory, IMPORT_DIRECTORY | SECURITY_DIRECTORY) {
            continue;
        }

        let Ok(Some(offset)) = model.directory_offset(directory) else {
            continue;
        };
        let Ok(Some(data)) = model.directory(restored, directory) else {
            continue;
        };

        let rva = data.rva().as_usize();
        let size = data.size() as usize;
        if !block.contains(&rva) {
            continue;
        }

        if directory == IAT_DIRECTORY {
            if write_u32(restored, offset, 0).is_err()
                || write_u32(restored, offset + 4, 0).is_err()
            {
                return false;
            }
            continue;
        }

        let Some(body) = restored
            .get(rva..rva.saturating_add(size))
            .map(<[u8]>::to_vec)
        else {
            return false;
        };
        let moved = match reclaim(restored, model, original, size) {
            Some(at) => {
                let Some(room) = restored.get_mut(at..at.saturating_add(size)) else {
                    return false;
                };
                room.copy_from_slice(&body);
                at
            }
            None => match append(restored, model, b".vmptab\0", DATA_SECTION, &body) {
                Some(at) => at,
                None => return false,
            },
        };

        let Ok(moved) = u32::try_from(moved) else {
            return false;
        };
        if write_u32(restored, offset, moved).is_err() {
            return false;
        }
    }

    true
}

fn table_references(restored: &[u8], model: &PeModel, base: usize) -> Vec<usize> {
    let directory = |index: usize| {
        model
            .directory(restored, index)
            .ok()
            .flatten()
            .map(|data| (data.rva().as_usize(), data.size() as usize))
    };
    let rva_at = |at: usize| read_u32(restored, at).ok().map(|rva| rva as usize);
    let pointer_at = |at: usize| {
        read_pointer(restored, at, model.kind())
            .ok()
            .and_then(|address| address.checked_sub(base))
    };
    let width = model.kind().pointer_width();
    let mut found = Vec::new();

    if let Some((at, _)) = directory(EXPORT_DIRECTORY) {
        found.extend(
            EXPORT_TABLE_FIELDS
                .iter()
                .filter_map(|field| rva_at(at.saturating_add(*field))),
        );

        let names = rva_at(at.saturating_add(EXPORT_NAMES_RVA)).unwrap_or(0);
        let count = rva_at(at.saturating_add(EXPORT_NAME_COUNT)).unwrap_or(0);
        found.extend(
            (0..count.min(MAX_TABLE_ENTRIES))
                .filter_map(|index| rva_at(names.saturating_add(index * 4))),
        );
    }

    if let Some((at, _)) = directory(TLS_DIRECTORY) {
        found.extend(
            (0..TLS_POINTER_FIELDS)
                .filter_map(|field| pointer_at(at.saturating_add(field * width))),
        );
    }

    if let Some((at, size)) = directory(DEBUG_DIRECTORY) {
        found.extend(
            (0..(size / DEBUG_ENTRY_SIZE).min(MAX_TABLE_ENTRIES)).filter_map(|index| {
                rva_at(at.saturating_add(index * DEBUG_ENTRY_SIZE + DEBUG_RAW_DATA_RVA))
            }),
        );
    }

    if let Some((at, size)) = directory(DELAY_IMPORT_DIRECTORY) {
        for index in 0..(size / DELAY_DESCRIPTOR_SIZE).min(MAX_TABLE_ENTRIES) {
            let descriptor = at.saturating_add(index * DELAY_DESCRIPTOR_SIZE);
            found.extend(
                DELAY_RVA_FIELDS
                    .iter()
                    .filter_map(|field| rva_at(descriptor.saturating_add(*field))),
            );

            let lookups = rva_at(descriptor.saturating_add(DELAY_LOOKUP_RVA)).unwrap_or(0);
            found.extend(
                (0..MAX_TABLE_ENTRIES)
                    .map_while(|slot| {
                        read_pointer(restored, lookups.saturating_add(slot * width), model.kind())
                            .ok()
                            .filter(|entry| *entry != 0)
                    })
                    .filter(|entry| entry >> (width * 8 - 1) == 0), // the top bit marks an ordinal
            );
        }
    }

    found
}

fn vmp_sections(model: &PeModel, block: &Range<usize>) -> Vec<Range<usize>> {
    model
        .sections()
        .iter()
        .map(|section| {
            let start = section.virtual_address().as_usize();
            start..start.saturating_add(section.span() as usize)
        })
        .filter(|section| block.contains(&section.start))
        .collect()
}

fn vmp_section_name(model: &PeModel) -> bool {
    model
        .sections()
        .iter()
        .any(|section| section.name().starts_with(b".vmp"))
}

fn vm_entry(bytes: &[u8], model: &PeModel, block: &Range<usize>) -> bool {
    let Ok(entry) = read_u32(bytes, model.entry_point_offset) else {
        return false;
    };
    let entry = entry as usize;
    let Some(code) = bytes.get(entry..entry.saturating_add(VM_ENTRY_LEN)) else {
        return false;
    };
    if code[0] != PUSH_IMM32 || code[5] != CALL_REL32 {
        return false;
    }

    let rel = i32::from_le_bytes([code[6], code[7], code[8], code[9]]);
    (entry + VM_ENTRY_LEN)
        .checked_add_signed(rel as isize)
        .is_some_and(|target| block.contains(&target))
}

fn drop_vm_relocations(
    restored: &mut [u8],
    model: &PeModel,
    sections: &[Range<usize>],
) -> Option<(usize, usize)> {
    let entry = model.directory_offset(BASERELOC_DIRECTORY).ok()??;
    let rva = read_u32(restored, entry).ok()? as usize;
    let size = read_u32(restored, entry + 4).ok()? as usize;
    let table = restored.get(rva..rva.checked_add(size)?)?.to_vec();

    let mut kept: Vec<u8> = Vec::with_capacity(table.len());
    let mut dropped = 0;
    let mut blocks = 0;
    let mut at = 0;
    while at + RELOCATION_BLOCK_HEADER <= table.len() {
        let page = read_u32(&table, at).ok()? as usize;
        let length = read_u32(&table, at + 4).ok()? as usize;
        if length < RELOCATION_BLOCK_HEADER || at.checked_add(length)? > table.len() {
            break; // a malformed tail is left where it is for the rebuild to judge
        }

        match sections.iter().any(|section| section.contains(&page)) {
            true => dropped += 1,
            false => {
                blocks += 1;
                kept.extend_from_slice(&table[at..at + length]);
            }
        }
        at += length;
    }

    let area = restored.get_mut(rva..rva + size)?;
    area.fill(0);
    area[..kept.len()].copy_from_slice(&kept);

    match kept.is_empty() {
        true => {
            write_u32(restored, entry, 0).ok()?;
            write_u32(restored, entry + 4, 0).ok()?;
        }
        false => write_u32(restored, entry + 4, u32::try_from(kept.len()).ok()?).ok()?,
    }
    Some((dropped, blocks))
}

fn shed(restored: &mut [u8], model: &PeModel, unused: &[Range<usize>]) -> usize {
    let mut dropped = 0;

    for section in model.sections() {
        let start = section.virtual_address().as_usize();
        if !unused.iter().any(|range| range.start == start) {
            continue;
        }

        let end = start
            .saturating_add(section.span() as usize)
            .min(restored.len());
        let Some(area) = restored.get_mut(start..end) else {
            continue;
        };
        dropped += area.len();
        area.fill(0);

        let _ = write_u32(
            restored,
            section.header_offset + SECTION_CHARACTERISTICS_OFFSET,
            BSS_SECTION,
        );
    }

    dropped
}

fn next_section_rva(restored: &[u8], model: &PeModel) -> Option<usize> {
    let image_size = read_u32(restored, model.size_of_image_offset).ok()? as usize;
    Some(image_size.next_multiple_of(model.section_alignment as usize))
}

fn append(
    restored: &mut Vec<u8>,
    model: &PeModel,
    name: &[u8; 8],
    characteristics: u32,
    contents: &[u8],
) -> Option<usize> {
    let rva = next_section_rva(restored, model)?;
    let image_end = rva.checked_add(
        contents
            .len()
            .next_multiple_of(model.section_alignment as usize),
    )?;
    (image_end <= MAX_IAT_IMAGE).then_some(())?;

    let count_at = model.nt_offset.checked_add(SECTION_COUNT_OFFSET)?;
    let count = read_u16(restored, count_at).ok()?;
    let first = model
        .sections()
        .iter()
        .map(|section| section.header_offset)
        .min()?;
    let header = first.checked_add(usize::from(count) * SECTION_HEADER_SIZE)?; // the next free slot since an earlier append may have taken one
    let headers_end = read_u32(restored, model.size_of_headers_offset).ok()? as usize;
    (header.checked_add(SECTION_HEADER_SIZE)? <= headers_end).then_some(())?;

    let size = u32::try_from(contents.len()).ok()?;
    let slot = restored.get_mut(header..header + SECTION_HEADER_SIZE)?;
    slot.fill(0);
    slot.get_mut(..8)?.copy_from_slice(name);
    write_u32(restored, header + SECTION_VIRTUAL_SIZE_OFFSET, size).ok()?;
    write_u32(
        restored,
        header + SECTION_RVA_OFFSET,
        u32::try_from(rva).ok()?,
    )
    .ok()?;
    write_u32(restored, header + 16, size).ok()?; // raw size
    write_u32(restored, header + 20, u32::try_from(rva).ok()?).ok()?; // raw pointer (memory image)
    write_u32(
        restored,
        header + SECTION_CHARACTERISTICS_OFFSET,
        characteristics,
    )
    .ok()?;
    write_u16(restored, count_at, count.checked_add(1)?).ok()?;
    write_u32(
        restored,
        model.size_of_image_offset,
        u32::try_from(image_end).ok()?,
    )
    .ok()?;

    restored.resize(image_end, 0);
    restored
        .get_mut(rva..rva + contents.len())?
        .copy_from_slice(contents);
    Some(rva)
}

fn resolve_imports(
    bytes: &[u8],
    model: &PeModel,
    vm: &Range<usize>,
    code: &[Range<usize>],
    vm_code: &mutation::Payload<'_>,
    origin: &Origin<'_>,
) -> (Vec<ResolvedImport>, usize) {
    let bits = match model.kind() {
        PeKind::Pe32 => 32,
        PeKind::Pe32Plus => 64,
    };
    let image_len = bytes.len();
    let payload = payload_start(bytes, model, vm);
    let stubs = stub_section(model, vm).unwrap_or(payload..image_len); // every direct branch in here is an import stub and any other is coincidence
    let mut found = Vec::new();
    let mut refused = 0;

    for branch in mutation::direct_branches(bytes, origin.base as u64, bits, code, vm_code) {
        if found.len() >= MAX_STUB_SITES {
            break;
        }
        if !stubs.contains(&branch.target) {
            continue;
        }

        match read_site(bytes, origin, bits, branch.site) {
            Reading::Import(site) => found.push(site),
            Reading::Refused => refused += 1,
            Reading::Stray => {}
        }
    }

    let total = found.len();
    let kept = drop_overlaps(found);
    refused += total - kept.len();
    (kept, refused)
}

enum Reading {
    Import(ResolvedImport),
    Refused, // a stub no single sound reading settles
    Stray,   // not an import stub at all
}

fn read_site(bytes: &[u8], origin: &Origin<'_>, bits: u32, at: usize) -> Reading {
    let mut chosen: Option<ResolvedImport> = None;
    let mut conflict = false;
    let mut stub_seen = false;

    for start in candidate_starts(bytes, at, bits) {
        let site = match place(bytes, origin, bits, start, at) {
            Ok(site) => site,
            Err(refusal) => {
                stub_seen |= refusal == Refusal::Stub;
                continue;
            }
        };
        match &chosen {
            None => chosen = Some(site),
            Some(kept) if kept.target == site.target && kept.form == site.form => {
                if site.len < kept.len {
                    chosen = Some(site); // a longer reading only swallowed a neutral byte in front
                }
            }
            Some(_) => conflict = true,
        }
    }

    match (chosen, conflict) {
        (Some(site), false) => Reading::Import(site),
        (Some(_), true) => Reading::Refused, // two sound readings so restoring either would be a guess
        (None, _) if stub_seen => Reading::Refused,
        (None, _) => Reading::Stray,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Refusal {
    Stray, // a call that only lands in vmp code by chance so it is common and not an import
    Stub,  // a real stub but no single sound reading
}

fn candidate_starts(bytes: &[u8], at: usize, bits: u32) -> Vec<usize> {
    let before = |back: usize| at.checked_sub(back).and_then(|p| bytes.get(p)).copied();

    let mut starts = vec![at];
    if before(1).is_some_and(|b| matches!(b, 0x50..=0x5F | 0x9C | 0x90)) {
        starts.push(at - 1); // a push pop pushf or nop in front of it
        if bits == 64 && before(2).is_some_and(|b| (0x40..=0x4F).contains(&b)) {
            starts.push(at - 2); // on x64 that byte may carry a rex prefix
        }
    }
    starts
}

fn place(
    bytes: &[u8],
    origin: &Origin<'_>,
    bits: u32,
    start: usize,
    at: usize,
) -> Result<ResolvedImport, Refusal> {
    let base = origin.base;
    let va = |offset: usize| base as u64 + offset as u64;
    let refusal = |failure| match failure {
        emu::Failure::Stray => Refusal::Stray,
        emu::Failure::Mismatch => Refusal::Stub,
    };
    let first = emu::resolve(bytes, base as u64, bits, va(start), va(at), 0).map_err(refusal)?;
    let second = emu::resolve(bytes, base as u64, bits, va(start), va(at), 1).map_err(refusal)?;

    let target = usize::try_from(first.target).map_err(|_| Refusal::Stray)?;
    if origin.exports.resolve(target).is_none() {
        return Err(Refusal::Stray); // not an export of a loaded module so the call only looked like a stub
    }
    let agree =
        first.target == second.target && first.flow == second.flow && first.end == second.end;
    if !agree {
        return Err(Refusal::Stub); // the two seeds disagree so the stub has no sound reading
    }

    let len = match first.end {
        Some(end) => end
            .checked_sub(va(start))
            .and_then(|len| usize::try_from(len).ok())
            .ok_or(Refusal::Stub)?,
        None => (at - start + REL_CALL_LEN).max(6), // a jump never returns so its span belongs to vmp
    };
    let form = match first.flow {
        emu::Flow::Call => ImportForm::Call,
        emu::Flow::Jump => ImportForm::Jump,
        emu::Flow::Load(reg) => ImportForm::Load(reg),
    };

    let fits = match form {
        ImportForm::Call | ImportForm::Jump => len == 6 || (bits == 64 && len == 7), // call/jmp [m] seven with a redundant rex w
        ImportForm::Load(_) if bits == 64 => len == 7, // a pointer load always carries rex w
        ImportForm::Load(reg) => len == 6 || (len == 5 && reg == 0), // five as the short a1 form for eax
    };
    if !fits || start + len > bytes.len() {
        return Err(Refusal::Stub);
    }

    Ok(ResolvedImport {
        site: start,
        len,
        form,
        target: first.target,
    })
}

fn drop_overlaps(mut sites: Vec<ResolvedImport>) -> Vec<ResolvedImport> {
    sites.sort_by_key(|site| site.site);

    let mut clash = vec![false; sites.len()];
    let mut reach: Option<(usize, usize)> = None; // furthest end so far and which site owns it
    for (index, site) in sites.iter().enumerate() {
        if let Some((end, owner)) = reach
            && site.site < end
        {
            clash[index] = true;
            clash[owner] = true; // two sites sharing bytes cannot both be real so neither is restored
        }
        let end = site.site + site.len;
        if reach.is_none_or(|(furthest, _)| end > furthest) {
            reach = Some((end, index));
        }
    }

    sites
        .into_iter()
        .zip(clash)
        .filter_map(|(site, clashed)| (!clashed).then_some(site))
        .collect()
}

fn encode(form: ImportForm, len: usize, kind: PeKind, disp: i32) -> Vec<u8> {
    let mut bytes = match form {
        ImportForm::Call | ImportForm::Jump => {
            let modrm = if form == ImportForm::Call { 0x15 } else { 0x25 }; // ff 15 = call [m] and ff 25 = jmp [m]
            if len == 7 {
                vec![0x48, 0xFF, modrm] // the seven byte form carries rex w
            } else {
                vec![0xFF, modrm]
            }
        }
        ImportForm::Load(reg) if kind == PeKind::Pe32Plus => {
            vec![0x48 | ((reg >> 3) << 2), 0x8B, ((reg & 7) << 3) | 0x05] // 8b /r with mod=00 rm=101 = mov reg [m]
        }
        ImportForm::Load(_) if len == 5 => vec![0xA1], // a1 = mov eax [m]
        ImportForm::Load(reg) => vec![0x8B, (reg << 3) | 0x05],
    };
    bytes.extend_from_slice(&disp.to_le_bytes());
    bytes
}

fn stub_section(model: &PeModel, vm: &Range<usize>) -> Option<Range<usize>> {
    let sections = model.sections();
    let entry = sections
        .iter()
        .position(|section| section.virtual_address().as_usize() == vm.start)?; // the packed entry point section
    let section = (1..entry)
        .rev()
        .map(|index| &sections[index])
        .find(|section| section.is_executable())?; // the vmp data section sits between it and the vm section holding the stubs

    (section.span() >= MIN_VM_SECTION).then(|| {
        let start = section.virtual_address().as_usize();
        start..start.saturating_add(section.span() as usize)
    })
}

fn payload_start(bytes: &[u8], model: &PeModel, vm: &Range<usize>) -> usize {
    if let Some(stubs) = stub_section(model, vm) {
        return stubs.start.min(vm.start);
    }

    let first = model
        .sections()
        .first()
        .map_or(0, |s| s.virtual_address().as_usize()); // the original program own section never payload
    let mut start = vm.start;
    for section in model.sections() {
        let at = section.virtual_address().as_usize();
        if at == first || !section.is_executable() || at >= start {
            continue;
        }
        let end = at.saturating_add(section.span() as usize).min(bytes.len());
        if bytes
            .get(at..end)
            .is_some_and(|data| entropy(data) >= PACKED_ENTROPY)
        {
            start = at;
        }
    }
    start
}

fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for byte in data.iter().step_by(ENTROPY_STEP) {
        counts[*byte as usize] += 1;
    }
    let total: u64 = counts.iter().sum();
    let total = total as f64;
    -counts
        .iter()
        .filter(|&&c| c != 0)
        .map(|&c| {
            let p = c as f64 / total;
            p * p.log2()
        })
        .sum::<f64>()
}

fn vm_section(bytes: &[u8], model: &PeModel) -> Option<Range<usize>> {
    let entry = read_u32(bytes, model.entry_point_offset).ok()? as usize;
    let (index, section) = model
        .sections()
        .iter()
        .enumerate()
        .find(|(_, section)| section.contains_rva(Rva(entry as u32)))?;

    let big_enough = section.span() >= MIN_VM_SECTION;
    let shape_ok = index > 0 && big_enough && section.is_executable();

    let start = section.virtual_address().as_usize();
    let end = start.checked_add(section.span() as usize)?;
    let points_here = |directory: usize| {
        model
            .directory(bytes, directory)
            .ok()
            .flatten()
            .is_some_and(|data| (start..end).contains(&data.rva().as_usize()))
    };

    let companions = COMPANION_DIRECTORIES
        .into_iter()
        .filter(|directory| points_here(*directory))
        .count(); // vmp moves these into the same appended section as the entry point
    (shape_ok
        && points_here(IMPORT_DIRECTORY)
        && (companions >= 1
            || bytes
                .get(start..end.min(bytes.len()))
                .is_some_and(|data| entropy(data) >= PACKED_ENTROPY))) // a minimal x86 program has no companion directory to confirm it
    .then_some(start..end)
}

fn original_entry(bytes: &[u8], model: &PeModel, vm: &Range<usize>, base: usize) -> Option<usize> {
    let code = original_code(bytes, model, vm);
    let x64 = model.kind() == PeKind::Pe32Plus;
    let subsystem = read_u16(
        bytes,
        model.size_of_image_offset + SUBSYSTEM_FROM_IMAGE_SIZE,
    )
    .ok()?;

    let candidates = [
        msvc_entry(bytes, &code, x64),
        mingw_entry(bytes, &code, x64, subsystem),
        go_entry(bytes, &code, x64),
        vb6_entry(bytes, &code, x64, base),
        delphi_entry(bytes, &code, x64, base),
        vc6_entry(bytes, &code, x64),
    ];

    let mut found = candidates.into_iter().flatten();
    let first = found.next()?;
    found.all(|other| other == first).then_some(first) // recognisers that disagree are all distrusted rather than guessed between
}

fn original_code(bytes: &[u8], model: &PeModel, vm: &Range<usize>) -> Vec<Range<usize>> {
    let payload = payload_start(bytes, model, vm);
    model
        .sections()
        .iter()
        .filter(|section| section.is_executable())
        .map(|section| {
            let start = section.virtual_address().as_usize();
            start
                ..start
                    .saturating_add(section.span() as usize)
                    .min(bytes.len())
        })
        .filter(|range| range.start < payload && range.start < range.end) // a stray match inside vmp payload would pass as a unique hit
        .collect()
}

fn hits(bytes: &[u8], code: &[Range<usize>], pattern: &str) -> Vec<usize> {
    code.iter()
        .flat_map(|range| {
            find_patterns(&bytes[range.clone()], pattern).map(move |offset| range.start + offset)
        })
        .collect()
}

fn unique(found: impl IntoIterator<Item = usize>) -> Option<usize> {
    let mut found = found.into_iter();
    let first = found.next()?;
    found.next().is_none().then_some(first)
}

fn msvc_entry(bytes: &[u8], code: &[Range<usize>], x64: bool) -> Option<usize> {
    let (pattern, skip) = if x64 {
        (MSVC_ENTRY_X64, 0)
    } else {
        (MSVC_ENTRY_X86, X86_ENTRY_SKIP)
    };
    unique(hits(bytes, code, pattern)).map(|at| at + skip)
}

fn mingw_entry(bytes: &[u8], code: &[Range<usize>], x64: bool, subsystem: u16) -> Option<usize> {
    let pattern = match subsystem {
        SUBSYSTEM_CONSOLE => MINGW_CONSOLE_X64,
        SUBSYSTEM_GUI => MINGW_GUI_X64,
        _ => return None,
    };
    if !x64 {
        return None;
    }
    unique(hits(bytes, code, pattern))
}

fn go_entry(bytes: &[u8], code: &[Range<usize>], x64: bool) -> Option<usize> {
    let body = unique(hits(bytes, code, if x64 { GO_RT0_X64 } else { GO_RT0_X86 }))?;
    unique(
        hits(bytes, code, "E9 ?? ?? ?? ??")
            .into_iter()
            .filter(|&at| rel32_target(bytes, at) == Some(body)),
    )
}

fn vb6_entry(bytes: &[u8], code: &[Range<usize>], x64: bool, base: usize) -> Option<usize> {
    if x64 {
        return None;
    }
    unique(hits(bytes, code, VB6_ENTRY).into_iter().filter(|&at| {
        absolute_rva(bytes, at + 1, base)
            .and_then(|header| bytes.get(header..header + VB6_HEADER_MAGIC.len()))
            .is_some_and(|magic| magic == VB6_HEADER_MAGIC)
    }))
}

fn delphi_entry(bytes: &[u8], code: &[Range<usize>], x64: bool, base: usize) -> Option<usize> {
    if x64 {
        return None;
    }
    let init = unique(hits(bytes, code, DELPHI_INIT).into_iter().filter(|&at| {
        absolute_rva(bytes, at + 1, base).is_some_and(|table| init_table(bytes, code, table, base))
    }))?;

    let reach = init.saturating_sub(DELPHI_FRAME_REACH)..init;
    unique(find_patterns(&bytes[reach.clone()], DELPHI_FRAME).map(|offset| reach.start + offset))
}

fn init_table(bytes: &[u8], code: &[Range<usize>], table: usize, base: usize) -> bool {
    let Ok(count) = read_u32(bytes, table) else {
        return false;
    };
    let Some(units) = absolute_rva(bytes, table + 4, base) else {
        return false;
    };
    if !(1..=MAX_DELPHI_UNITS).contains(&count) || units + count as usize * 8 > bytes.len() {
        return false;
    }

    let in_code = |rva: usize| code.iter().any(|range| range.contains(&rva));
    let (mut pointers, mut into_code) = (0usize, 0usize);
    for index in 0..(count as usize).min(16) {
        for half in 0..2 {
            let Ok(pointer) = read_u32(bytes, units + index * 8 + half * 4) else {
                return false;
            };
            if pointer == 0 {
                continue;
            }
            match (pointer as usize).checked_sub(base) {
                Some(rva) if rva < bytes.len() => {
                    pointers += 1;
                    into_code += usize::from(in_code(rva));
                }
                _ => return false,
            }
        }
    }
    into_code >= 2 && into_code * 2 >= pointers // a stray mov eax imm then call never points most of a table into code
}

fn vc6_entry(bytes: &[u8], code: &[Range<usize>], x64: bool) -> Option<usize> {
    if x64 {
        return None;
    }
    unique(hits(bytes, code, VC6_ENTRY))
}

fn rel32_target(bytes: &[u8], at: usize) -> Option<usize> {
    let rel = i32::from_le_bytes(bytes.get(at + 1..at + 5)?.try_into().ok()?);
    (at + REL_CALL_LEN).checked_add_signed(rel as isize)
}

fn absolute_rva(bytes: &[u8], at: usize, base: usize) -> Option<usize> {
    let rva = (read_u32(bytes, at).ok()? as usize).checked_sub(base)?;
    (rva < bytes.len()).then_some(rva)
}
