mod compiler_encodings;
mod demutation;
mod entry_point;
mod imports;
mod mutated_function;
mod original_instruction;
mod reassembly;
mod sdk_macros;
mod sections;

use std::ops::Range;

use crate::packers::{NAMED_BY_CONTENTS, Packer, sections_before};
use crate::pe::bytes::read_u32;
use crate::pe::{
    EXCEPTION_DIRECTORY, FUNCTION_END_OFFSET, IMPORT_DIRECTORY, PeImage, PeKind, PeModel,
    RUNTIME_FUNCTION_SIZE, SectionModel, UNWIND_INFO_OFFSET,
};
use crate::unpack::tables::{
    pogo_parts, pogo_sections, pogo_tls_directory, recover_directories,
    restore_exception_directory, restore_relocation_directory, restore_tls,
};
use crate::unpack::x86::branches::{Branch, JUMP_REL32, direct_branches, rel32_target};
use crate::unpack::x86::opcodes::{INT3, NOP, RET};
use crate::unpack::x86::{StubRunner, WrapperLeadsTo};
use crate::unpack::{Origin, PackerId, PackerReport, Part, Unpacked};

const WINLICENSE_SECTION: &[u8] = b".winlice"; // default name is all that marks winlicense
const SECTION_NAMES: [&[u8]; 3] = [b".themida", WINLICENSE_SECTION, b".boot"]; // defaults a project can rename
const MIN_ENGINE_SECTION: u32 = 0x8_0000; // its virtual machines and wrappers alone run to hundreds of kilobytes
const FUNCTION_ALIGNMENT: usize = 16;
const BEFORE_A_FUNCTION: [u8; 3] = [INT3, NOP, RET];
const FUNCTION_BEGIN: usize = 0;
const UNWIND_FLAGS_SHIFT: u8 = 3; // version in the low three bits
const UNWIND_CHAIN_INFO: u8 = 0x4;

pub(super) struct Functions(Vec<Range<usize>>); // x64 exception directory, by start

impl Functions {
    pub(super) fn read(image: &[u8], model: &PeModel) -> Self {
        let directory = match model.kind {
            PeKind::Pe32Plus => model.directory(image, EXCEPTION_DIRECTORY),
            PeKind::Pe32 => None,
        };
        let table = directory
            .and_then(|directory| {
                let start = directory.rva().as_usize();
                image.get(start..start.checked_add(directory.size() as usize)?)
            })
            .unwrap_or_default();

        let mut entries: Vec<(Range<usize>, bool)> = table
            .as_chunks::<RUNTIME_FUNCTION_SIZE>()
            .0
            .iter()
            .filter_map(|entry| {
                let begin = read_u32(entry.as_slice(), FUNCTION_BEGIN).ok()? as usize;
                let end = read_u32(entry.as_slice(), FUNCTION_END_OFFSET).ok()? as usize;
                let unwind = read_u32(entry.as_slice(), UNWIND_INFO_OFFSET).ok()? as usize;
                let flags = image
                    .get(unwind)
                    .map_or(0, |byte| byte >> UNWIND_FLAGS_SHIFT);
                (begin < end).then_some((begin..end, flags & UNWIND_CHAIN_INFO != 0))
            })
            .collect();
        entries.sort_unstable_by_key(|(extent, _)| extent.start);

        let mut extents: Vec<Range<usize>> = Vec::with_capacity(entries.len());
        for (extent, chained) in entries {
            match extents.last_mut() {
                Some(last) if chained && last.end == extent.start => last.end = extent.end, // a fragment of the function before it
                _ => extents.push(extent),
            }
        }

        Self(extents)
    }

    pub(super) fn containing(&self, at: usize) -> Option<&Range<usize>> {
        let after = self.0.partition_point(|extent| extent.start <= at);
        self.0
            .get(after.checked_sub(1)?)
            .filter(|extent| extent.contains(&at))
    }

    pub(super) fn starts(&self) -> impl Iterator<Item = usize> + '_ {
        self.0.iter().map(|extent| extent.start)
    }
}

pub(super) fn aligned_or_after_int3(image: &[u8], at: usize) -> bool {
    at.is_multiple_of(FUNCTION_ALIGNMENT)
        || at.checked_sub(1).and_then(|before| image.get(before)) == Some(&INT3)
}

pub(super) fn opens_section_or_follows_padding(
    bytes: &[u8],
    code: &[Range<usize>],
    at: usize,
) -> bool {
    code.iter().any(|range| range.start == at)
        || at
            .checked_sub(1)
            .and_then(|before| bytes.get(before))
            .is_some_and(|before| BEFORE_A_FUNCTION.contains(before))
}

pub(super) fn jumps_into(bytes: &[u8], at: usize, range: &Range<usize>) -> bool {
    bytes.get(at) == Some(&JUMP_REL32)
        && rel32_target(bytes, at).is_some_and(|target| range.contains(&target))
}

struct Layout {
    original_end: usize,
    engine: Range<usize>,
    variables: Range<usize>,
    boot: usize,
    named: bool,
}

struct Packed<'a> {
    image: &'a PeImage<'a>,
    origin: &'a Origin<'a>,
    layout: Layout,
    code: Vec<Range<usize>>,
}

impl<'a> Packed<'a> {
    fn new(image: &'a PeImage<'a>, origin: &'a Origin<'a>) -> Option<Self> {
        let layout = layout(image.bytes(), image.model())?;
        let code = sections_before(image.bytes(), image.model(), layout.original_end, true);

        Some(Self {
            image,
            origin,
            layout,
            code,
        })
    }

    fn model(&self) -> &PeModel {
        self.image.model()
    }

    fn kind(&self) -> PeKind {
        self.model().kind
    }

    fn runner(&self) -> StubRunner<'_> {
        StubRunner {
            image: self.image.bytes(),
            base: self.origin.base as u64,
            bits: self.kind().bits(),
            memory: self.origin.memory,
        }
    }

    fn va(&self, range: &Range<usize>) -> Range<u64> {
        let base = self.origin.base as u64;
        base + range.start as u64..base + range.end as u64
    }

    fn boots_through_vm(&self) -> bool {
        let runner = self.runner();
        let loader = runner.base + self.layout.boot as u64;
        let engine = self.va(&self.layout.engine);
        runner.destination(loader, &engine) == Some(WrapperLeadsTo::VirtualMachine) // themida's loader runs in its vm
    }

    fn tail(&self) -> Range<usize> {
        self.layout.original_end..self.image.bytes().len()
    }

    fn branches(&self, restored: &[u8]) -> Vec<Branch> {
        let runner = self.runner();
        direct_branches(restored, runner.base, runner.bits, &self.code, &|_| None)
    }

    fn branches_into_tail(&self, restored: &[u8]) -> Vec<Branch> {
        let tail = self.tail();
        let mut branches = self.branches(restored);
        branches.retain(|branch| tail.contains(&branch.target));
        branches
    }
}

fn original_code(image: &PeImage<'_>) -> Option<Vec<Range<usize>>> {
    let layout = layout(image.bytes(), image.model()).filter(|layout| layout.named)?; // the shape alone fits other packers
    Some(sections_before(
        image.bytes(),
        image.model(),
        layout.original_end,
        true,
    ))
}

fn unpack(image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
    let model = image.model();
    let packed = Packed::new(image, origin)?;
    let layout = &packed.layout;
    if !(layout.named || packed.boots_through_vm()) {
        return None; // layout alone fits other packers
    }

    let name = match section_named(model, WINLICENSE_SECTION) {
        true => PackerId::WinLicense,
        false => PackerId::Themida,
    };
    let mut report = PackerReport::new(name, None);
    let mut restored = image.bytes().to_vec();

    let imports = imports::restore(&mut restored, &packed);
    let entry = entry_point::restore(&mut restored, &packed, &mut report);
    if !imports.wrapped() && entry.is_none() {
        let reason = "nothing shows themida had unpacked it: no import it wrapped, no entry point";
        return Some(Unpacked::detected_only(name, None, reason));
    }

    let iat = imports.declare(&mut restored, &packed, &mut report)?;

    let parts = pogo_parts(&restored, model, layout.original_end);
    let tls = restore_tls(
        &mut restored,
        model,
        origin.base,
        layout.original_end,
        parts.as_deref().and_then(pogo_tls_directory),
    );
    report.record(Part::Tls, tls);

    recover_directories(
        &mut restored,
        model,
        origin.base,
        layout.original_end,
        &origin.writable_sections(model),
        &mut report,
    );

    let exceptions = restore_exception_directory(&mut restored, model, layout.original_end);
    report.record(Part::Exceptions, exceptions);

    let relocations =
        restore_relocation_directory(&mut restored, model, origin.base, layout.original_end);
    if relocations.is_some() {
        report.restored(Part::Relocations);
    }

    let tables = sections::Tables {
        iat: imports.table_start(),
        entry,
        relocations,
        linked: parts
            .as_deref()
            .and_then(|parts| pogo_sections(parts, &restored, model, layout.original_end, entry))
            .unwrap_or_default(),
    };
    sections::mark_relocations_discardable(&mut restored, &packed, relocations);
    match sections::name(&mut restored, &packed, &tables) {
        sections::Named::FromLinker => report.restored(Part::SectionNames),
        sections::Named::Inferred => {
            report.inferred(Part::SectionNames, NAMED_BY_CONTENTS);
        }
        sections::Named::Nothing => {}
    }

    let unmutated = demutation::analyse(&restored, &packed); // runs themida's code: before its sections go
    sections::drop_engine(&mut restored, &packed, &mut report);
    demutation::apply(&mut restored, &packed, &unmutated, &mut report);
    sdk_macros::clean(&mut restored, &packed, &unmutated, &mut report);

    Unpacked::restored(restored, report, Some(iat), None).ok()
}

fn layout(bytes: &[u8], model: &PeModel) -> Option<Layout> {
    let entry = read_u32(bytes, model.entry_point_offset).ok()? as usize;
    let mut sections: Vec<&SectionModel> = model.sections.iter().collect();
    sections.sort_unstable_by_key(|section| section.virtual_address().as_usize());

    let boot = sections
        .iter()
        .position(|section| section.range().contains(&entry))?;
    let engine_like =
        |section: &SectionModel| section.is_executable() && section.span() >= MIN_ENGINE_SECTION;

    let own_imports = model
        .directory(bytes, IMPORT_DIRECTORY)
        .and_then(|directory| {
            sections
                .iter()
                .map(|section| section.range())
                .find(|range| range.contains(&directory.rva().as_usize()))
        })
        .map(|range| range.start);

    let behind_tables =
        |section: &SectionModel| own_imports.is_none_or(|tables| section.range().start >= tables);
    let first = sections
        .get(..=boot)?
        .iter()
        .position(|section| engine_like(section) && behind_tables(section))
        .or_else(|| {
            let before = boot.checked_sub(1)?;
            engine_like(sections.get(before)?).then_some(before)
        })
        .or_else(|| engine_like(sections.get(boot)?).then_some(boot))?;
    if first == 0 {
        return None;
    }

    let engine = sections.get(first)?.range().start..sections.get(boot)?.range().end;
    let own_imports = own_imports.unwrap_or(engine.start);

    Some(Layout {
        original_end: own_imports.min(engine.start),
        variables: sections.get(first)?.range(),
        engine,
        boot: entry,
        named: SECTION_NAMES.iter().any(|name| section_named(model, name)),
    })
}

fn section_named(model: &PeModel, name: &[u8]) -> bool {
    model
        .sections
        .iter()
        .any(|section| section.name().starts_with(name))
}

pub(super) struct Themida;

impl Packer for Themida {
    fn unpack(&self, image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
        unpack(image, origin)
    }

    fn original_code(&self, image: &PeImage<'_>, _base: usize) -> Option<Vec<Range<usize>>> {
        original_code(image)
    }
}
