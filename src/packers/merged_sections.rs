use std::ops::Range;

use super::SPLIT_BY_HEADER;
use crate::pe::bytes::{read_u32, write_u32};
use crate::pe::parse::{parse_disk_image, parse_memory_image};
use crate::pe::{
    BASERELOC_DIRECTORY, BOUND_IMPORT_DIRECTORY, DEBUG_ADDRESS_OFFSET, DEBUG_DIRECTORY,
    DEBUG_SIZE_OFFSET, DELAY_IMPORT_DIRECTORY, LOAD_CONFIG_DIRECTORY, PeImage, PeModel,
    RESOURCE_DIRECTORY, SECTION_HEADER_SIZE, TIMESTAMP_OFFSET, map_disk_image,
};
use crate::unpack::codecs::bitstream::ByteTags;
use crate::unpack::codecs::{DecodeError, aplib};
use crate::unpack::tables::{
    CoffGroup, Fixups, LinkerBounds, PlannedSection, ResourceLayout, Restoration, SectionHints,
    SectionKind, THUNK_SIZE, apply_listed_imports, clear_header_slack, code_stores_into,
    debug_entries, debug_timestamp, find_relocation_table, first_section_range, header_code_range,
    iat_span, lay_out_resources, linker_bounds, lowest_leaf_below, name_sections, pogo_parts,
    pogo_sections, pogo_tls_directory, recover_directories, relocations_intact, repair_icon_groups,
    replace_first_section, resource_layout, resource_leaf, restore_moved_resources, restore_tls,
    security_cookie, split_merged_section, walk_resources,
};
use crate::unpack::x86::compiler_entry::vb6_data_start;
use crate::unpack::x86::opcodes::{LEA, MODRM_DISP32, MODRM_DISP32_MASK, MOV_IMM_RM};
use crate::unpack::x86::opcodes::{MOV_REG_IMM32, POP_REG, PUSH_IMM32};
use crate::unpack::{
    InitialData, ModuleImports, Origin, PACKER_HEADER_BYTES, PackerId, PackerImports, PackerReport,
    Part, Step, Unpacked, need, with_initial_data,
};

pub(super) const MAX_CANDIDATES: usize = 32;
pub(super) const MAX_STREAMS: usize = 256;
pub(super) const TOO_MANY: &str = "too many stub candidates to tell apart";
pub(super) const MODIFIED_STUB: &str = "(modified stub)";
const DISAGREE: &str = "several stub candidates unpack to different programs";

const DATA_NAME: [u8; 8] = *b".data\0\0\0";
const SPLIT_BY_STREAMS: &str = "from packed streams, table positions and observed writes";

pub(super) const EBX: u8 = 3;
pub(super) const ESI: u8 = 6;
pub(super) const EDI: u8 = 7;

pub(super) struct Load {
    pub(super) at: usize,
    pub(super) register: u8,
    pub(super) value: usize,
}

pub(super) struct ListedImports {
    pub(super) modules: Vec<ModuleImports>,
    pub(super) end_markers: Vec<usize>,
    pub(super) written: Range<usize>,
    pub(super) names_end: usize,
    pub(super) inferred: Option<&'static str>,
}

pub(super) enum Undecided {
    Failed(DecodeError),
    Disagree,
}

impl Undecided {
    pub(super) fn describe(&self) -> &'static str {
        match self {
            Self::Failed(why) => why.describe(),
            Self::Disagree => DISAGREE,
        }
    }
}

pub(super) struct Placed {
    pub(super) range: Range<usize>,
    pub(super) consumed: usize,
    pub(super) beneath: Vec<u8>,
}

// fsg and mew unpack every section into one region and keep no section table of the program
pub(super) struct MergedImage {
    pub(super) name: PackerId,
    pub(super) version: &'static str,
    pub(super) entry: usize,
    pub(super) entry_inferred: Option<&'static str>,
    pub(super) program_inferred: Option<&'static str>,
    pub(super) program: Range<usize>,
    pub(super) image_end: usize,
    pub(super) original: Vec<u8>,
    pub(super) beneath_imports: Option<(usize, Vec<u8>)>,
    pub(super) imports: Option<ListedImports>,
    pub(super) section_starts: Option<Vec<usize>>,
    pub(super) keeps_code_fields: bool,
}

struct Located {
    bounds: Option<LinkerBounds>,
    kept_code: Option<Range<usize>>,
    resources: Option<usize>,
    relocations: Option<Range<usize>>,
    declared_data: Option<usize>,
}

struct Evidence<'a> {
    memory: &'a [u8],
    original: &'a [u8],
    base: usize,
    bits: u32,
    finished: bool,
    stub_writes: [Range<usize>; 2],
    constants_start: Option<usize>,
    names_end: usize,
}

impl Evidence<'_> {
    fn written(&self, range: Range<usize>) -> bool {
        self.finished
            && range.into_iter().any(|at| {
                !self.stub_writes.iter().any(|written| written.contains(&at))
                    && self.memory.get(at) != self.original.get(at)
            })
    }

    // the program ran and left it alone, or, before it ran, none of its code stores to it directly
    fn stays_clean(&self, range: Range<usize>, code: &Range<usize>) -> bool {
        match self.finished {
            true => !self.written(range),
            false => !self.stores_into(code, &range),
        }
    }

    // the program wrote it once it ran, or its code stores to it directly, run or not
    fn writes_to(&self, range: Range<usize>, code: &Range<usize>) -> bool {
        self.stores_into(code, &range) || self.written(range)
    }

    fn stores_into(&self, code: &Range<usize>, range: &Range<usize>) -> bool {
        code_stores_into(self.original, self.base, self.bits, code, range)
    }
}

struct Restore<'a> {
    restored: Vec<u8>,
    report: PackerReport,
    model: &'a PeModel,
    original: &'a [u8],
    base: usize,
    writable: Vec<Range<usize>>,
    entry: usize,
    program: Range<usize>,
    image_end: usize,
}

struct SectionPlan {
    pieces: Option<Vec<PlannedSection>>,
    from_linker: bool,
    resources: Option<usize>,
}

pub(super) fn refused(name: PackerId, version: &str, reason: &'static str) -> Option<Unpacked> {
    let version = Some(version.to_owned());
    Some(Unpacked::detected_only(name, version, reason))
}

pub(super) fn restore(
    image: &PeImage<'_>,
    origin: &Origin<'_>,
    merged: MergedImage,
) -> Option<Unpacked> {
    let (name, version) = (merged.name, merged.version);
    let restored = restore_merged(image, origin, merged);

    Some(
        restored
            .unwrap_or_else(|refusal| Unpacked::refused(name, Some(version.to_owned()), refusal)),
    )
}

fn restore_merged(image: &PeImage<'_>, origin: &Origin<'_>, merged: MergedImage) -> Step<Unpacked> {
    let MergedImage {
        name,
        version,
        entry,
        entry_inferred,
        program_inferred,
        program,
        image_end,
        original,
        beneath_imports,
        imports: listed,
        section_starts,
        keeps_code_fields,
    } = merged;
    let original = original.as_slice();
    let model = image.model();
    let page = model.section_alignment as usize;
    let section_starts = section_starts.map(|starts| {
        starts
            .into_iter()
            .filter(|start| start.is_multiple_of(page)) // a stream that starts mid-page opens no section
            .collect::<Vec<_>>()
    });

    let mut work = Restore {
        restored: image.bytes().to_vec(),
        report: PackerReport::new(name, Some(version.to_owned())),
        model,
        original,
        base: origin.base,
        writable: origin.writable_sections(model),
        entry,
        program: program.clone(),
        image_end,
    };

    let layout = resource_layout(
        image.bytes(),
        model,
        listed
            .iter()
            .flat_map(|listed| &listed.modules)
            .filter_map(|module| module.module.as_deref()),
    );

    let finished = listed
        .as_ref()
        .is_some_and(|listed| stub_finished(image.bytes(), original, &listed.modules));
    if !finished {
        let copied = work.copy_program(program_inferred);
        need(copied, "the unpacked program does not fit the image")?;
    }
    let evidence = stub_evidence(
        image.bytes(),
        original,
        origin.base,
        model.kind.bits(),
        finished,
        listed.as_ref(),
    );

    work.write_entry(entry_inferred)?;
    let imports = work.write_imports(listed);
    need(
        work.return_bytes_beneath_imports(beneath_imports.as_ref()),
        "the bytes under the packer's import list do not fit the image",
    )?;

    let kept_relocations =
        find_relocation_table(original, &program, origin.base, page, Fixups::Pristine);
    let pogo = pogo_parts(&work.restored, model, program.end);

    let plan = work.place_resources_and_plan(
        pogo.as_deref(),
        layout,
        kept_relocations.as_ref(),
        section_starts,
        keeps_code_fields,
        &evidence,
    );
    need(
        work.repair_small_tables(pogo.as_deref()),
        "the build timestamp does not fit the headers",
    )?;

    let relocations = check_relocations(&mut work.restored, model, program.end, kept_relocations);
    let unreported = matches!(relocations, Restoration::Absent);
    work.report.record(Part::Relocations, relocations);

    model.clear_directory(&mut work.restored, BOUND_IMPORT_DIRECTORY);
    if clear_header_slack(&mut work.restored) {
        work.report.notes.push(PACKER_HEADER_BYTES.to_string()); // before new headers need the room
    }

    work.write_section_table(plan, &evidence);
    if unreported && relocation_section_emptied(&work.restored, program.end) {
        work.report.lost(Part::Relocations);
    }

    let fresh = finished
        .then(|| {
            with_initial_data(
                image.bytes(),
                &work.restored,
                InitialData {
                    bytes: original,
                    base: origin.linked_base().unwrap_or(origin.base), // from the file: link time pointers
                },
                origin.base,
                program.end,
                &[],
            )
        })
        .flatten();

    Unpacked::restored(work.restored, work.report, imports, fresh)
}

pub(super) fn write_entry(restored: &mut [u8], model: &PeModel, entry: usize) -> Step<()> {
    let written = u32::try_from(entry)
        .ok()
        .and_then(|entry| write_u32(restored, model.entry_point_offset, entry).ok());
    need(written, "the entry point does not fit its header field")
}

fn stub_evidence<'a>(
    memory: &'a [u8],
    original: &'a [u8],
    base: usize,
    bits: u32,
    finished: bool,
    listed: Option<&ListedImports>,
) -> Evidence<'a> {
    let iat = listed.and_then(|listed| {
        iat_span(
            listed
                .modules
                .iter()
                .map(|module| (module.first_thunk as usize, module.functions.len())),
            THUNK_SIZE,
        )
        .map(|(start, size)| start..start.saturating_add(size))
    });

    Evidence {
        memory,
        original,
        base,
        bits,
        finished,
        stub_writes: [
            iat.clone().unwrap_or_default(),
            listed
                .map(|listed| listed.written.clone())
                .unwrap_or_default(),
        ],
        constants_start: iat.as_ref().map(|iat| iat.start),
        names_end: listed.map_or(0, |listed| listed.names_end),
    }
}

impl Restore<'_> {
    fn copy_program(&mut self, inferred: Option<&'static str>) -> Option<()> {
        let program = self.program.clone();
        self.restored
            .get_mut(program.clone())?
            .copy_from_slice(self.original.get(program)?);

        match inferred {
            Some(how) => self.report.inferred(Part::CodeAndData, how),
            None => self
                .report
                .restored_with(Part::CodeAndData, "from the packed data"),
        }
        Some(())
    }

    fn write_entry(&mut self, inferred: Option<&'static str>) -> Step<()> {
        write_entry(&mut self.restored, self.model, self.entry)?;

        match inferred {
            Some(how) => self.report.inferred(Part::EntryPoint, how),
            None => self.report.restored(Part::EntryPoint),
        }
        Ok(())
    }

    fn write_imports(&mut self, listed: Option<ListedImports>) -> Option<PackerImports> {
        let inferred = listed.as_ref().and_then(|listed| listed.inferred);
        let imports = listed.and_then(
            |ListedImports {
                 modules,
                 end_markers,
                 ..
             }| {
                for slot in end_markers {
                    write_u32(&mut self.restored, slot, 0).ok()?;
                }
                apply_listed_imports(&mut self.restored, self.model, modules)
            },
        );

        match (&imports, inferred) {
            (Some(_), Some(how)) => self.report.inferred(Part::Imports, how),
            (Some(_), None) => self.report.restored(Part::Imports),
            (None, _) => self.report.failed(Part::Imports),
        }
        imports
    }

    fn return_bytes_beneath_imports(&mut self, beneath: Option<&(usize, Vec<u8>)>) -> Option<()> {
        let Some((at, beneath)) = beneath else {
            return Some(());
        };

        self.restored
            .get_mut(*at..at.checked_add(beneath.len())?)?
            .copy_from_slice(beneath);
        Some(())
    }

    fn place_resources_and_plan(
        &mut self,
        pogo: Option<&[CoffGroup]>,
        layout: ResourceLayout,
        kept_relocations: Option<&Range<usize>>,
        section_starts: Option<Vec<usize>>,
        keeps_code_fields: bool,
        evidence: &Evidence<'_>,
    ) -> SectionPlan {
        let (model, end, entry) = (self.model, self.program.end, self.entry);
        let page = model.section_alignment as usize;
        let linked_resources = pogo.and_then(|parts| {
            parts
                .iter()
                .filter(|part| part.name.starts_with(b".rsrc"))
                .map(|part| part.rva)
                .min()
        });

        let moved = lowest_leaf_below(&self.restored, model, end);
        let kept_in_packer = match moved {
            Some(_) => None,
            None => resources_at_image_end(
                &mut self.restored,
                model,
                self.image_end,
                layout,
                self.original,
                kept_relocations,
                linked_resources,
            ),
        };
        let resources = moved.or(kept_in_packer);

        let linker_pieces =
            pogo.and_then(|parts| pogo_sections(parts, &self.restored, model, end, Some(entry)));
        let from_linker = linker_pieces.is_some();
        let bounds = keeps_code_fields
            .then(|| linker_bounds(&self.restored, model, entry))
            .flatten();
        let kept_code = (keeps_code_fields && bounds.is_none())
            .then(|| kept_code(&self.restored, model, &self.program, entry))
            .flatten();
        let pieces = linker_pieces.or_else(|| {
            let located = Located {
                bounds,
                kept_code,
                resources,
                relocations: kept_relocations.cloned(),
                declared_data: vb6_data_start(&self.restored, entry, self.base),
            };
            Some(stream_sections(
                section_starts?,
                page,
                entry,
                evidence,
                located,
                self.program.clone(),
            ))
        });

        let ranges: Vec<Range<usize>> = match &pieces {
            Some(pieces) => pieces.iter().map(|piece| piece.start..piece.end).collect(),
            None => resources
                .into_iter()
                .map(|leaf| leaf..self.image_end)
                .collect(), // fsg 2.0 packs leaves from .rsrc start
        };
        match kept_in_packer {
            Some(_) => self.report.inferred(
                Part::Resources,
                "laid out in the zero pages before the image's end",
            ),
            None => {
                let moved = restore_moved_resources(
                    &mut self.restored,
                    model,
                    &ranges,
                    end,
                    layout,
                    Some(self.original),
                );
                self.report.record(Part::Resources, moved);
            }
        }

        if has_blank_leaf(&self.restored, model) {
            self.report.lost(Part::ResourceData); // fsg 2.0 zeroes DVCLAL and PACKAGEINFO
        }

        SectionPlan {
            pieces,
            from_linker,
            resources,
        }
    }

    fn repair_small_tables(&mut self, pogo: Option<&[CoffGroup]>) -> Option<()> {
        let (model, base, end) = (self.model, self.base, self.program.end);

        let laid_out = 0..self.image_end; // fsg 1.x overwrites a group's tail; the leaves were laid out again since
        let icons = repair_icon_groups(&mut self.restored, model, &laid_out);
        self.report.record(Part::IconGroups, icons);

        let tls = restore_tls(
            &mut self.restored,
            model,
            base,
            end,
            pogo.and_then(pogo_tls_directory),
        );
        self.report.record(Part::Tls, tls);

        recover_directories(
            &mut self.restored,
            model,
            base,
            end,
            &self.writable,
            &mut self.report,
        );

        if let Some(timestamp) = debug_timestamp(&self.restored, model) {
            let at = model.nt_offset.checked_add(TIMESTAMP_OFFSET)?;
            if read_u32(&self.restored, at).ok() != Some(timestamp) {
                write_u32(&mut self.restored, at, timestamp).ok()?;
                self.report.restored(Part::BuildTimestamp);
            }
        }
        Some(())
    }

    fn write_section_table(&mut self, plan: SectionPlan, evidence: &Evidence<'_>) {
        let how = match plan.pieces {
            Some(_) => SPLIT_BY_STREAMS,
            None => SPLIT_BY_HEADER,
        };
        let sections = match plan.pieces {
            Some(pieces) if pieces.is_empty() => None,
            Some(pieces) => replace_first_section(&mut self.restored, self.model, &pieces),
            None => split_merged(
                &mut self.restored,
                self.model,
                self.base,
                self.entry,
                evidence,
                plan.resources,
                self.image_end,
            ),
        };

        match (sections.is_some(), plan.from_linker) {
            (true, true) => self.report.restored(Part::SectionTable),
            (true, false) => {
                self.report.inferred(Part::SectionSplit, how);
                self.report.lost(Part::SectionTable);
            }
            (false, _) => self.report.lost(Part::SectionTable),
        }
    }
}

pub(super) fn register_load(bytes: &[u8], at: usize) -> Option<Load> {
    let code = bytes.get(at..)?;
    let immediate = |offset: usize| read_u32(code, offset).ok().map(|value| value as usize);

    let (register, value) = match *code.first()? {
        opcode if (MOV_REG_IMM32..MOV_REG_IMM32 + 8).contains(&opcode) => {
            (opcode - MOV_REG_IMM32, immediate(1)?)
        }
        PUSH_IMM32 => match *code.get(5)? {
            pop if (POP_REG..POP_REG + 8).contains(&pop) => (pop - POP_REG, immediate(1)?),
            _ => return None,
        },
        LEA => {
            let modrm = *code.get(1)?;
            let address = modrm & MODRM_DISP32_MASK == MODRM_DISP32;
            address.then_some(((modrm >> 3) & 7, immediate(2)?))?
        }
        MOV_IMM_RM => {
            let modrm = *code.get(1)?;
            (modrm & 0xF8 == 0xC0).then_some((modrm & 7, immediate(2)?))?
        }
        _ => return None,
    };

    Some(Load {
        at,
        register,
        value,
    })
}

pub(super) fn address(bytes: &[u8], at: usize, base: usize) -> Option<usize> {
    (read_u32(bytes, at).ok()? as usize).checked_sub(base)
}

pub(super) fn outside(image: &Range<usize>, length: usize) -> [Range<usize>; 2] {
    [0..image.start, image.end..length]
}

pub(super) fn blank_program(packed: &[u8], program: &Range<usize>) -> Result<Vec<u8>, DecodeError> {
    let mut image = packed.to_vec();
    image
        .get_mut(program.clone())
        .ok_or(DecodeError::Truncated)?
        .fill(0); // streams cover initialized data only
    Ok(image)
}

pub(super) fn place_stream(
    packed: &[u8],
    source: usize,
    image: &mut [u8],
    destination: usize,
    end: usize,
) -> Result<Placed, DecodeError> {
    let mut tags = ByteTags::new(packed.get(source..).ok_or(DecodeError::Truncated)?);
    let limit = end.checked_sub(destination).ok_or(DecodeError::Corrupt)?;
    let decoded = aplib::decompress(&mut tags, limit, aplib::Variant::Classic)?;

    let range = destination
        ..destination
            .checked_add(decoded.len())
            .ok_or(DecodeError::Corrupt)?;
    let target = image.get_mut(range.clone()).ok_or(DecodeError::Truncated)?;
    let beneath = target.to_vec();
    target.copy_from_slice(&decoded);

    Ok(Placed {
        range,
        consumed: tags.position(),
        beneath,
    })
}

pub(super) fn consensus<T: PartialEq>(
    attempts: impl Iterator<Item = Result<T, DecodeError>>,
) -> Result<T, Undecided> {
    let mut why = DecodeError::Corrupt;
    let mut found: Option<T> = None;
    for attempt in attempts {
        match attempt {
            Err(error) => why = error,
            Ok(decoded) => match &found {
                Some(first) if decoded != *first => return Err(Undecided::Disagree),
                Some(_) => {}
                None => found = Some(decoded),
            },
        }
    }

    found.ok_or(Undecided::Failed(why))
}

pub(super) fn consensus_decoding<T>(
    image: &PeImage<'_>,
    origin: &Origin<'_>,
    decode_all: impl Fn(&[u8]) -> Result<T, Undecided>,
) -> Result<T, Undecided> {
    match decode_all(image.bytes()) {
        Err(Undecided::Failed(why)) => {
            let file = origin.read_file();
            let mapped = file.and_then(|file| mapped_file(file, image));
            mapped.map_or(Err(Undecided::Failed(why)), |mapped| decode_all(&mapped))
        }
        decided => decided,
    }
}

pub(super) fn mapped_file(file: &[u8], image: &PeImage<'_>) -> Option<Vec<u8>> {
    let disk = parse_disk_image(file).ok()?;
    let model = disk.model();

    same_headers(file, model, image.bytes(), image.model()).then_some(())?;
    map_disk_image(file, model.image_size as usize)
}

fn same_headers(file: &[u8], disk: &PeModel, memory: &[u8], mapped: &PeModel) -> bool {
    let same_field = |disk_at: usize, mapped_at: usize| {
        let field = read_u32(file, disk_at).ok();
        field.is_some() && field == read_u32(memory, mapped_at).ok()
    };
    let same_section = |disk_at: usize, mapped_at: usize| {
        let header = file.get(disk_at..disk_at.saturating_add(SECTION_HEADER_SIZE));
        let mapped = memory.get(mapped_at..mapped_at.saturating_add(SECTION_HEADER_SIZE));
        header.is_some() && header == mapped
    };

    disk.image_size == mapped.image_size
        && same_field(disk.entry_point_offset, mapped.entry_point_offset)
        && same_field(
            disk.nt_offset.saturating_add(TIMESTAMP_OFFSET),
            mapped.nt_offset.saturating_add(TIMESTAMP_OFFSET),
        )
        && same_field(disk.checksum_offset(), mapped.checksum_offset())
        && disk.sections.len() == mapped.sections.len()
        && disk
            .sections
            .iter()
            .zip(&mapped.sections)
            .all(|(disk, mapped)| same_section(disk.header_offset, mapped.header_offset))
}

fn kept_code(
    restored: &[u8],
    model: &PeModel,
    program: &Range<usize>,
    entry: usize,
) -> Option<Range<usize>> {
    let page = model.section_alignment as usize;
    let Range { start, end } = header_code_range(restored, model)?;

    let fits = start.is_multiple_of(page)
        && program.start < start
        && end <= program.end
        && (start..end).contains(&entry);
    fits.then_some(start..end)
}

fn lay_out_or_undo(
    restored: &mut [u8],
    model: &PeModel,
    root: usize,
    blank: Range<usize>,
    layout: ResourceLayout,
    pristine: &[u8],
) -> Option<()> {
    let first = model.sections.first()?.virtual_address().as_usize();
    let headers = restored.get(..first)?.to_vec();

    let laid_out = lay_out_resources(restored, model, root, blank.clone(), layout, Some(pristine));
    if laid_out.is_none() {
        restored.get_mut(..first)?.copy_from_slice(&headers);
        restored.get_mut(blank)?.fill(0);
    }

    laid_out
}

fn resources_at_image_end(
    restored: &mut [u8],
    model: &PeModel,
    image_end: usize,
    layout: ResourceLayout,
    pristine: &[u8],
    relocations: Option<&Range<usize>>,
    linked_start: Option<usize>,
) -> Option<usize> {
    let page = model.section_alignment as usize;
    let last_relocations =
        relocations.filter(|table| table.end.next_multiple_of(page) >= image_end);
    let tree_end = match last_relocations {
        Some(table) => table.start,
        None => {
            (!model.relocatable(restored)).then_some(())?;
            image_end
        }
    };

    let root = model
        .directory(restored, RESOURCE_DIRECTORY)?
        .rva()
        .as_usize();
    (root >= image_end).then_some(())?;

    let first = model.sections.first()?.virtual_address().as_usize();
    let linked_start = linked_start.filter(|start| {
        (first..tree_end).contains(start)
            && restored
                .get(*start..tree_end)
                .is_some_and(|area| area.iter().all(|byte| *byte == 0))
    });
    if let Some(start) = linked_start
        && lay_out_or_undo(restored, model, root, start..tree_end, layout, pristine).is_some()
    {
        return Some(start);
    }

    let mut start = tree_end;

    while start > first {
        start = start.checked_sub(page)?;
        restored
            .get(start..start.checked_add(page)?)?
            .iter()
            .all(|byte| *byte == 0)
            .then_some(())?;
        if lay_out_or_undo(restored, model, root, start..tree_end, layout, pristine).is_some() {
            return Some(start);
        }
    }

    None
}

fn has_blank_leaf(restored: &[u8], model: &PeModel) -> bool {
    let Some(root) = model
        .directory(restored, RESOURCE_DIRECTORY)
        .map(|directory| directory.rva().as_usize())
    else {
        return false;
    };

    walk_resources(restored, root).is_some_and(|tree| {
        tree.data_entries.iter().any(|entry| {
            let data = resource_leaf(restored, root, *entry)
                .and_then(|(_, rva, size)| restored.get(rva..rva.checked_add(size)?));
            data.is_some_and(|data| !data.is_empty() && data.iter().all(|byte| *byte == 0))
        })
    })
}

fn stream_sections(
    starts: Vec<usize>,
    page: usize,
    entry: usize,
    evidence: &Evidence<'_>,
    located: Located,
    image: Range<usize>,
) -> Vec<PlannedSection> {
    let Located {
        bounds,
        kept_code,
        resources,
        relocations,
        declared_data,
    } = located;
    let end = image.end;
    let relocation_bounds =
        relocations.map(|table| [table.start, table.end.next_multiple_of(page)]);
    let starts: Vec<usize> = [image.start]
        .into_iter()
        .chain(starts)
        .chain(
            bounds
                .into_iter()
                .flat_map(|bounds| [Some(bounds.code_end), bounds.data])
                .flatten(),
        )
        .chain(resources.filter(|start| start.is_multiple_of(page)))
        .chain(relocation_bounds.into_iter().flatten())
        .filter(|start| image.contains(start))
        .collect();
    let declared_code = bounds
        .map(|bounds| image.start..bounds.code_end)
        .or(kept_code.filter(|code| starts.contains(&code.start)));

    let entry_piece_end = starts
        .iter()
        .copied()
        .filter(|start| *start > entry)
        .min()
        .unwrap_or(end);
    let code = declared_code
        .clone()
        .unwrap_or(image.start..entry_piece_end);
    let constants = evidence.constants_start.filter(|iat| {
        let piece_start = starts.iter().copied().filter(|start| start <= iat).max();
        let piece_end = starts
            .iter()
            .copied()
            .filter(|start| start > iat)
            .min()
            .unwrap_or(end);
        piece_start.is_some_and(|piece_start| evidence.stays_clean(piece_start..piece_end, &code))
    });

    let hints = SectionHints {
        code: Some(entry),
        code_end: Some(bounds.map_or(entry_piece_end, |bounds| bounds.code_end)), // linkers put code first
        constants,
        relocations: relocation_bounds.map(|[start, _]| start),
        resources,
    };

    let mut pieces = Vec::new();
    for piece in name_sections(starts, end, &hints, bounds.is_some()) {
        if piece.kind == SectionKind::WritableCode
            && evidence.writes_to(piece.start..piece.end, &code)
        {
            pieces.push(PlannedSection {
                kind: SectionKind::Data, // the program writes it: data
                ..piece
            });
            continue;
        }
        if piece.kind != SectionKind::Code {
            pieces.push(piece);
            continue;
        }
        if declared_code
            .as_ref()
            .is_some_and(|code| piece.end <= code.start)
        {
            pieces.push(PlannedSection {
                name: DATA_NAME,
                kind: SectionKind::Data,
                ..piece
            });
            continue;
        }

        let written = first_written_page(evidence, &piece, page, entry); // writes after the entry mean merged data
        let declared = declared_data.filter(|data| {
            data.is_multiple_of(page)
                && *data > entry
                && (piece.start.saturating_add(1)..piece.end).contains(data)
        });
        let data = declared.or(written);

        let head = piece.start..data.unwrap_or(piece.end);
        let kind = code_kind(&head, entry, declared_code.as_ref(), evidence);
        pieces.push(PlannedSection {
            end: head.end,
            kind,
            ..piece
        });
        if let Some(data) = data {
            pieces.push(PlannedSection {
                name: DATA_NAME,
                start: data,
                end: piece.end,
                kind: SectionKind::Data,
            });
        }
    }

    pieces
}

fn code_kind(
    piece: &Range<usize>,
    entry: usize,
    declared_code: Option<&Range<usize>>,
    evidence: &Evidence<'_>,
) -> SectionKind {
    let declared =
        declared_code.is_some_and(|code| code.start <= piece.start && piece.end <= code.end);
    let ran_clean = piece.contains(&entry) && evidence.finished;

    match (declared || ran_clean) && !evidence.written(piece.clone()) {
        true => SectionKind::Code,
        false => SectionKind::WritableCode, // unknown or written: the superset
    }
}

fn first_written_page(
    evidence: &Evidence<'_>,
    piece: &PlannedSection,
    page: usize,
    entry: usize,
) -> Option<usize> {
    (piece.start..piece.end)
        .step_by(page)
        .skip(1)
        .filter(|start| *start > entry)
        .find(|start| evidence.written(*start..start.saturating_add(page).min(piece.end)))
}

fn split_merged(
    restored: &mut [u8],
    model: &PeModel,
    base: usize,
    entry: usize,
    evidence: &Evidence<'_>,
    resources: Option<usize>,
    image_end: usize,
) -> Option<()> {
    let page = model.section_alignment as usize;
    let constants_end = read_only_end(restored, model).max(evidence.names_end);
    let constants_page = constants_end.checked_next_multiple_of(page);
    let data = match security_cookie(restored, model, base) {
        Some(cookie) => constants_page.map(|constants| constants.min(cookie / page * page)), // msvc: first page of .data
        None => constants_page,
    };

    let split = evidence
        .constants_start
        .zip(data)
        .filter(|(constants, data)| {
            let code = first_section_range(model).zip(linker_bounds(restored, model, entry));
            let code = code.map_or(0..0, |(section, bounds)| section.start..bounds.code_end);
            constants < data && evidence.stays_clean(*constants..*data, &code)
        });

    let hints = SectionHints {
        code: Some(entry),
        code_end: None,
        constants: split.map(|(constants, _)| constants),
        relocations: None,
        resources,
    };

    split_merged_section(
        restored,
        model,
        &hints,
        split.map(|(_, data)| data),
        Some(image_end),
    )
}

fn read_only_end(restored: &[u8], model: &PeModel) -> usize {
    let directory_end = |index: usize| {
        let directory = model.directory(restored, index)?;
        directory
            .rva()
            .as_usize()
            .checked_add(directory.size() as usize)
    };

    let debug_data_end = debug_entries(restored, model)
        .filter_map(|entry| {
            let size = read_u32(restored, entry.checked_add(DEBUG_SIZE_OFFSET)?).ok()?;
            let rva = read_u32(restored, entry.checked_add(DEBUG_ADDRESS_OFFSET)?).ok()?;
            (rva as usize).checked_add(size as usize)
        })
        .max()
        .unwrap_or(0);

    [
        LOAD_CONFIG_DIRECTORY,
        DEBUG_DIRECTORY,
        DELAY_IMPORT_DIRECTORY,
    ]
    .into_iter()
    .filter_map(directory_end)
    .chain([debug_data_end])
    .max()
    .unwrap_or(0)
}

fn stub_finished(memory: &[u8], original: &[u8], modules: &[ModuleImports]) -> bool {
    modules
        .iter()
        .rev()
        .find(|module| !module.functions.is_empty())
        .is_some_and(|module| {
            let last = module
                .functions
                .len()
                .checked_sub(1)
                .and_then(|index| index.checked_mul(THUNK_SIZE))
                .and_then(|offset| (module.first_thunk as usize).checked_add(offset)); // stubs fill slots in order
            let filled = last.and_then(|slot| read_u32(memory, slot).ok());
            let packed = last.and_then(|slot| read_u32(original, slot).ok());

            filled.is_some_and(|value| value != 0) && filled != packed
        })
}

fn relocation_section_emptied(restored: &[u8], end: usize) -> bool {
    let Ok(image) = parse_memory_image(restored) else {
        return false;
    };
    let model = image.model();
    let stripped = model.directory(restored, BASERELOC_DIRECTORY).is_none();

    stripped
        && model.sections.iter().any(|section| {
            section.name().starts_with(b".reloc\0")
                && section.virtual_address().as_usize() < end
                && restored
                    .get(section.range())
                    .is_some_and(|table| table.iter().all(|byte| *byte == 0))
        })
}

fn check_relocations(
    restored: &mut [u8],
    model: &PeModel,
    end: usize,
    kept: Option<Range<usize>>,
) -> Restoration {
    let directory = model.directory(restored, BASERELOC_DIRECTORY);

    let intact = directory.is_some_and(|directory| {
        let start = directory.rva().as_usize();
        start < end && relocations_intact(restored, start, directory.size() as usize)
    });
    if intact {
        return Restoration::Absent;
    }

    let reattached = kept.is_some_and(|table| {
        model
            .set_directory(restored, BASERELOC_DIRECTORY, table.start, table.len())
            .is_some()
    });
    if reattached {
        return Restoration::Restored;
    }

    model.clear_directory(restored, BASERELOC_DIRECTORY);

    match model.relocatable(restored) {
        true => Restoration::Lost,
        false => Restoration::Absent,
    }
}
