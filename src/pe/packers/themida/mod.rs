mod entry;
mod imports;
mod macros;
mod mutation;
mod sections;

use std::ops::Range;

use super::branches::{Branch, direct_branches};
use super::emu::{Destination, Snapshot};
use super::tables::{
    pogo_parts, pogo_sections, pogo_tls_directory, recover_directories,
    restore_exception_directory, restore_relocation_directory, restore_tls,
};
use super::{Origin, PackerFindings, PackerReport, Unpacked};
use crate::pe::image::read_u32;
use crate::pe::parse::parse_memory_image;
use crate::pe::{IMPORT_DIRECTORY, PeImage, PeKind, PeModel, SectionModel};

const THEMIDA: &str = "Themida";
const WINLICENSE: &str = "WinLicense";
const WINLICENSE_SECTION: &[u8] = b".winlice"; // only the default name tells winlicense from themida
const SECTION_NAMES: [&[u8]; 3] = [b".themida", WINLICENSE_SECTION, b".boot"]; // the defaults, which a project can rename
const MIN_ENGINE_SECTION: u32 = 0x8_0000; // the virtual machines and wrappers alone run to hundreds of kilobytes

struct Layout {
    original_end: usize,
    engine: Range<usize>,
    variables: Range<usize>, // the engine without the loader's section, where it keeps its state
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
        let code = program_code(image, layout.original_end);

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
        self.model().kind()
    }

    fn snapshot(&self) -> Snapshot<'_> {
        Snapshot {
            image: self.image.bytes(),
            base: self.origin.base as u64,
            bits: self.kind().bits(),
            memory: self.origin.memory,
        }
    }

    fn engine(&self) -> Range<u64> {
        let base = self.origin.base as u64;
        base + self.layout.engine.start as u64..base + self.layout.engine.end as u64
    }

    fn boots_through_vm(&self) -> bool {
        let snapshot = self.snapshot();
        let loader = snapshot.base + self.layout.boot as u64;
        snapshot.destination(loader, &self.engine()) == Some(Destination::VirtualMachine) // themida runs its own loader in its virtual machine
    }

    fn tail(&self) -> Range<usize> {
        self.layout.original_end..self.image.bytes().len()
    }

    fn code(&self) -> &[Range<usize>] {
        &self.code
    }

    fn branches(&self, restored: &[u8]) -> Vec<Branch> {
        let snapshot = self.snapshot();
        direct_branches(restored, snapshot.base, snapshot.bits, &self.code, &|_| {
            None
        })
    }

    fn branches_into_tail(&self, restored: &[u8]) -> Vec<Branch> {
        let tail = self.tail();
        let mut branches = self.branches(restored);
        branches.retain(|branch| tail.contains(&branch.target));
        branches
    }
}

fn program_code(image: &PeImage<'_>, original_end: usize) -> Vec<Range<usize>> {
    let image_end = image.bytes().len();
    image
        .model()
        .sections()
        .iter()
        .filter(|section| section.is_executable())
        .map(|section| section.range().start..section.range().end.min(image_end))
        .filter(|range| range.start < original_end && range.start < range.end)
        .collect()
}

pub(super) fn unpack(image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
    let model = image.model();
    let packed = Packed::new(image, origin)?;
    let layout = &packed.layout;

    let name = match section_named(model, WINLICENSE_SECTION) {
        true => WINLICENSE,
        false => THEMIDA,
    };
    let mut report = PackerReport::new(name, None);
    let mut restored = image.bytes().to_vec();

    let imports = imports::restore(&mut restored, &packed);
    let entry = entry::restore(&mut restored, &packed, &mut report);
    if !imports.wrapped() {
        let identified = layout.named || packed.boots_through_vm(); // the layout alone fits other packers too
        if !(identified && entry.is_some()) {
            let reason = "image (nothing shows themida had unpacked it: no import it wrapped, no entry point)";
            return identified.then(|| Unpacked::detected_only(name, None, reason));
        }
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
    report.record("original TLS directory", tls);

    recover_directories(
        &mut restored,
        model,
        origin.base,
        layout.original_end,
        &mut report,
    );

    let exceptions = restore_exception_directory(&mut restored, model, layout.original_end);
    report.record("exception directory", exceptions);

    let relocations =
        restore_relocation_directory(&mut restored, model, origin.base, layout.original_end);
    if relocations.is_some() {
        report.restored.push("relocations");
    }

    let tables = sections::Tables {
        iat: imports.table_start(),
        entry,
        relocations,
        linked: parts
            .as_deref()
            .and_then(|parts| pogo_sections(parts, model, layout.original_end, entry))
            .unwrap_or_default(),
    };
    if sections::name(&mut restored, &packed, &tables) {
        report.restored.push("section names");
    }

    let mutated = mutation::analyse(&restored, &packed); // runs themida's own code, so before its sections go
    sections::drop_engine(&mut restored, &packed, &mut report);
    mutation::apply(&mut restored, &packed, &mutated, &mut report);
    macros::clean(&mut restored, &packed, &mut report);
    parse_memory_image(&restored).ok()?;

    Some(Unpacked {
        image: Some(restored),
        findings: PackerFindings {
            report,
            imports: iat,
        },
        fresh: None,
    })
}

fn layout(bytes: &[u8], model: &PeModel) -> Option<Layout> {
    let entry = read_u32(bytes, model.entry_point_offset).ok()? as usize;
    let mut sections: Vec<&SectionModel> = model.sections().iter().collect();
    sections.sort_unstable_by_key(|section| section.virtual_address().as_usize());

    let boot = sections
        .iter()
        .position(|section| section.range().contains(&entry))?;
    let engine_like =
        |section: &SectionModel| section.is_executable() && section.span() >= MIN_ENGINE_SECTION;

    let first = match boot.checked_sub(1).and_then(|before| sections.get(before)) {
        Some(before) if engine_like(before) => boot - 1, // the loader's own section follows the engine
        _ if engine_like(sections.get(boot)?) => boot,
        _ => return None,
    };
    if first == 0 {
        return None;
    }

    let engine = sections.get(first)?.range().start..sections.get(boot)?.range().end;
    let own_imports = model
        .directory(bytes, IMPORT_DIRECTORY)
        .ok()
        .flatten()
        .and_then(|directory| {
            sections
                .iter()
                .map(|section| section.range())
                .find(|range| range.contains(&directory.rva().as_usize()))
        })
        .map_or(engine.start, |range| range.start); // themida's import, tls and resource sections sit between the program and the engine

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
        .sections()
        .iter()
        .any(|section| section.name().starts_with(name))
}

fn counted(count: usize, one: &str, many: &str) -> String {
    match count {
        1 => format!("1 {one}"),
        _ => format!("{count} {many}"),
    }
}
