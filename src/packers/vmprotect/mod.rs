mod demutation;
mod imports;
mod layout;
mod wiped_tables;

use std::ops::{Range, RangeInclusive};

use iced_x86::{Instruction, OpKind};

use self::layout::Layout;
use self::wiped_tables::WipedTables;
use crate::import_recovery::code_referenced_slots;
use crate::packers::Packer;
use crate::pe::bytes::{read_pointer, read_u32, write_u32};
use crate::pe::exports::imported_dlls;
use crate::pe::{PeImage, PeKind, PeModel};
use crate::unpack::tables::{
    SectionKind, append, drop_relocation_blocks, evacuate, keep_unwind_within, next_section_rva,
    recover_directories, shed, table_references,
};
use crate::unpack::x86;
use crate::unpack::x86::branches::{
    CALL_REL32, JUMP_REL32, REL32_LEN, instructions, is_near_immediate, rel32_target, relative,
    set_rel32_target,
};
use crate::unpack::x86::compiler_entry::{compiler_entry, msvc_startup_slots};
use crate::unpack::{
    Origin, PackerFindings, PackerId, PackerImports, PackerReport, Part, Unpacked, counted,
};

const NAME: PackerId = PackerId::VmProtect;
const CLEANED_CODE_SECTION: &[u8; 8] = b".vmpcode";
const MOVED_TABLES_SECTION: &[u8; 8] = b".vmptab\0";
const IAT_SECTION: &[u8; 8] = b".vmpiat\0";
const OWN_SECTIONS: [&[u8; 8]; 3] = [CLEANED_CODE_SECTION, MOVED_TABLES_SECTION, IAT_SECTION];

const TWO_BYTE_OPCODE: u8 = 0x0F;
const JCC_REL32: RangeInclusive<u8> = 0x80..=0x8F; // second byte of 0f 8x
const JCC_REL32_LEN: usize = 6;
const JCC_OPERAND: usize = 2;

const UNCONFIRMED: &str = "recognised by its sections, but no import stub, mutated function or bound import slot shows its loader ran, so it was left as it is";

fn original_code(image: &PeImage<'_>) -> Option<Vec<Range<usize>>> {
    Layout::of(image)
        .filter(|layout| layout.vmp_marks) // the shape alone fits other packers
        .map(|layout| layout.code)
}

// on disk vmp leaves junk in the program's own import slots; only its loader puts exports there
fn loader_bound(image: &PeImage<'_>, origin: &Origin<'_>, layout: &Layout) -> bool {
    let kind = image.model().kind;

    code_referenced_slots(image, origin.base, std::slice::from_ref(&layout.block))
        .into_iter()
        .filter(|slot| !layout.block.contains(slot))
        .filter_map(|slot| read_pointer(image.bytes(), slot, kind).ok())
        .any(|value| origin.exports.resolve(value).is_some())
}

fn recognised(image: &PeImage<'_>) -> bool {
    Layout::of(image).is_some_and(|layout| layout.vmp_marks || layout.runtime_data)
}

fn unpack(image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
    let model = image.model();
    let layout = Layout::of(image)?;
    let bits = model.kind.bits();
    let base = origin.base as u64;

    let mut report = PackerReport::new(NAME, None);
    let mut restored = image.bytes().to_vec();
    let payload = demutation::Payload::new(image.bytes(), origin, bits, layout.payload());

    let demutated = restore_mutated(image, &mut restored, &layout.code, &payload, base);
    let code: Vec<Range<usize>> = layout
        .code
        .iter()
        .cloned()
        .chain(demutated.code.clone())
        .collect();
    let linked = imported_dlls(image);
    let mut found = imports::resolve(&restored, bits, &layout, &code, &payload, origin, linked);

    let stubs_confirmed = !found.resolved.is_empty(); // a branch into them reached an export
    let confirmed = stubs_confirmed
        || (layout.vmp_marks && (demutated.written > 0 || loader_bound(image, origin, &layout)));
    if !confirmed {
        return layout.vmp_marks.then(|| {
            let mut detected = Unpacked::detected_only(NAME, None, UNCONFIRMED);
            detected.findings.packer_ranges = vec![layout.block.clone()]; // its section names say whose they are
            detected
        });
    }

    demutated.describe(&mut report);
    let x64 = model.kind == PeKind::Pe32Plus;
    let msvc = compiler_entry(&restored, model, &layout.code, origin.base)
        .is_some_and(|entry| !msvc_startup_slots(&restored, entry, x64, origin.base).is_empty());
    let entries = found.vm_entries.iter().chain(&demutated.relocated.rejected);
    found.virtualized =
        imports::virtualized_calls(&restored, bits, &layout, origin, &found, entries);
    let rebuilt = imports::rebuild(&mut restored, model, &found, msvc, origin);
    describe_imports(&mut report, &found, rebuilt.is_some());

    recover_directories(
        &mut restored,
        model,
        origin.base,
        layout.payload(),
        &origin.writable_sections(model),
        &mut report,
    );
    let unwind = drop_vm_unwind(&mut restored, model, &layout, &mut report);
    WipedTables {
        model,
        layout: &layout,
        base: origin.base,
    }
    .restore(&mut restored, &mut report);
    restore_entry(&mut restored, model, &layout, origin.base, &mut report);

    let emptied = drop_sections(
        &mut restored,
        model,
        &layout,
        origin.base,
        &code,
        &mut report,
    );
    if !emptied && unwind > 0 {
        report.lost_with(Part::Unwind, "for the packer's own code, which is kept");
    }

    let moved_behind = model
        .sections
        .iter()
        .any(|section| section.range().start >= layout.block.end);
    if moved_behind {
        report.lost(Part::SectionTable); // vmp re-adds .rsrc and .reloc behind its own sections
    }
    if found.unresolved.enters_packer_code() {
        report.lost_with(
            Part::VirtualizedCode,
            "the program still enters the packer's code",
        );
    }

    Some(Unpacked {
        image: Some(restored),
        findings: PackerFindings {
            report,
            imports: rebuilt.unwrap_or(PackerImports::Unknown),
            packer_ranges: match emptied {
                true => Vec::new(),
                false => vec![layout.block.clone()],
            },
        },
        fresh: None,
    })
}

#[derive(Default)]
struct Demutated {
    relocated: demutation::Relocated,
    written: usize,
    code: Option<Range<usize>>,
}

impl Demutated {
    fn describe(&self, report: &mut PackerReport) {
        let demutation::Relocated {
            moved,
            rejected,
            unencodable,
            truncated,
            ..
        } = &self.relocated;
        let cleaned = moved.len();

        if cleaned > 0 {
            report.notes.push(match self.code {
                Some(_) => format!(
                    "{cleaned} mutated functions cleaned into .vmpcode, {} of them matched vmp's copy on every emulated test run and are aimed at from the original code",
                    self.written
                ),
                None => format!(
                    "{cleaned} mutated functions cleaned, but there was no room to add .vmpcode for them"
                ),
            });
        }
        if !rejected.is_empty() {
            report.notes.push(format!(
                "{} jumps into vmp's code left as they are: what they reach did not decode whole, ends in an indirect jump, or cleans to under {} instructions",
                rejected.len(),
                demutation::MIN_REAL_INSNS
            ));
        }
        if *unencodable > 0 {
            report.notes.push(format!(
                "{unencodable} cleaned functions could not be encoded again"
            ));
        }
        if *truncated {
            report.notes.push(format!(
                "only the first {} jump targets in vmp's code were read",
                demutation::MAX_TARGETS
            ));
        }

        let uncleaned = !rejected.is_empty() || *unencodable > 0 || *truncated;
        if uncleaned {
            report.lost_with(
                Part::MutatedCode,
                "some jumps into the packer's code could not be cleaned",
            );
        } else if self.written < cleaned {
            report.lost_with(Part::MutatedCode, "could not be written back");
        }
    }
}

fn restore_mutated(
    image: &PeImage<'_>,
    restored: &mut Vec<u8>,
    code: &[Range<usize>],
    payload: &demutation::Payload<'_>,
    base: u64,
) -> Demutated {
    let model = image.model();
    let bits = model.kind.bits();
    let Some(at) = next_section_rva(restored, model) else {
        return Demutated::default();
    };

    let relocated =
        demutation::reencode(image.bytes(), base, bits, code, payload, base + at as u64);
    let placed = !relocated.code.is_empty()
        && append(
            restored,
            model,
            CLEANED_CODE_SECTION,
            SectionKind::Code,
            &relocated.code,
        ) == Some(at);
    if !placed {
        return Demutated {
            relocated,
            ..Demutated::default()
        };
    }

    let written = relocated
        .moved
        .iter()
        .filter(|moved| aim_at_clean_copy(image.bytes(), restored, moved, base, bits))
        .count();
    let code = Some(at..at + relocated.code.len());
    Demutated {
        relocated,
        written,
        code,
    }
}

fn aim_at_clean_copy(
    captured: &[u8],
    restored: &mut [u8],
    moved: &demutation::Moved,
    base: u64,
    bits: u32,
) -> bool {
    let jump = moved.site + 1..moved.site + REL32_LEN;
    let Some(original) = restored.get(jump.clone()).map(<[u8]>::to_vec) else {
        return false;
    };
    let aimed = usize::try_from(moved.entry.wrapping_sub(base))
        .ok()
        .and_then(|entry| set_rel32_target(restored, moved.site, entry));
    if aimed.is_none() {
        return false;
    }

    let site = base + moved.site as u64;
    let same = x86::same_behaviour(
        captured,
        restored,
        base,
        bits,
        site,
        &(0..0),
        x86::Agreement::Every,
    );
    if !same {
        restored[jump].copy_from_slice(&original);
    }
    same
}

fn describe_imports(report: &mut PackerReport, found: &imports::Found, rebuilt: bool) {
    match (found.resolved.is_empty(), found.sites, rebuilt) {
        (false, _, true) => report.restored(Part::Imports),
        (false, _, false) => report.failed_with(Part::Imports, "no room for a rebuilt table"),
        (true, 0, _) => report.failed_with(
            Part::Imports,
            "no call into the packer's stub section was found",
        ),
        (true, _, _) => report.failed_with(
            Part::Imports,
            "calls into the packer's stub section were found, but none resolved",
        ),
    }

    let resolved = found.resolved.len();
    if found.placed_by_branches > 0 {
        report.notes.push(format!(
            "{} tail jumps with a nop in front placed where no branch lands on the byte they cover (inferred: their stub never returns)",
            found.placed_by_branches
        ));
    }
    if !found.virtualized.is_empty() {
        report.notes.push(format!(
            "{} imports only virtualized code calls were added to the table; those calls stay inside the virtual machine",
            found.virtualized.len()
        ));
    }
    let left = found.unresolved.describe();
    if found.unresolved.total() > 0 {
        report.partly_failed(Part::VmCalls, "see the notes for why");
    }
    if resolved > 0 || !left.is_empty() {
        report.notes.push(format!(
            "{resolved} import call sites rebuilt; left as they are: {}",
            match left.is_empty() {
                true => "none".to_string(),
                false => left.join(", "),
            }
        ));
    }
}

fn drop_vm_unwind(
    restored: &mut [u8],
    model: &PeModel,
    layout: &Layout,
    report: &mut PackerReport,
) -> usize {
    let dropped = keep_unwind_within(restored, model, &layout.code).unwrap_or(0);
    if dropped > 0 {
        report.notes.push(format!(
            "{dropped} exception-table entries outside the program's code dropped"
        ));
    }
    dropped
}

fn restore_entry(
    restored: &mut [u8],
    model: &PeModel,
    layout: &Layout,
    base: usize,
    report: &mut PackerReport,
) {
    let Some(entry) = compiler_entry(restored, model, &layout.code, base) else {
        report.failed_with(Part::EntryPoint, "no known compiler entry found");
        return;
    };

    let written = u32::try_from(entry)
        .ok()
        .and_then(|entry| write_u32(restored, model.entry_point_offset, entry).ok());
    match written {
        Some(()) => report.inferred(
            Part::EntryPoint,
            "recognised from the compiler's startup code",
        ),
        None => report.failed_with(Part::EntryPoint, "the entry found does not fit the header"),
    }
}

struct Reach {
    entry: bool,
    branches: usize,
    operands: usize,
    pointers: usize,
    tables: usize,
}

impl Reach {
    fn of(
        restored: &[u8],
        model: &PeModel,
        layout: &Layout,
        base: usize,
        code: &[Range<usize>],
    ) -> Self {
        let block = &layout.block;
        let kind = model.kind;
        let entry = read_u32(restored, model.entry_point_offset)
            .is_ok_and(|entry| block.contains(&(entry as usize)));

        let program = model
            .sections
            .iter()
            .map(|section| section.range_in(restored))
            .filter(|section| section.start < block.start);
        let added = code
            .iter()
            .filter(|range| range.start >= block.end)
            .cloned();
        let pointers = program
            .chain(added)
            .map(|range| pointers_into(restored, kind, base, &range, block))
            .sum();

        let tables = table_references(restored, model, base)
            .iter()
            .filter(|rva| block.contains(rva))
            .count();

        Self {
            entry,
            branches: code
                .iter()
                .map(|range| branches_into(restored, range, block))
                .sum(),
            operands: operands_into(restored, base as u64, kind.bits(), code, block),
            pointers,
            tables,
        }
    }

    fn is_empty(&self) -> bool {
        !self.entry
            && self.branches == 0
            && self.operands == 0
            && self.pointers == 0
            && self.tables == 0
    }

    fn describe(&self) -> String {
        let entry = match self.entry {
            true => "the entry point, ",
            false => "",
        };
        format!(
            "vmp's sections kept: {entry}{}, {}, {} and {} still lead into them",
            counted(self.branches, "branch displacement", "branch displacements"),
            counted(self.operands, "decoded operand", "decoded operands"),
            counted(self.pointers, "stored pointer", "stored pointers"),
            counted(self.tables, "table pointer", "table pointers"),
        )
    }
}

fn branches_into(bytes: &[u8], range: &Range<usize>, block: &Range<usize>) -> usize {
    let target = |at: usize| match bytes.get(at) {
        Some(&CALL_REL32 | &JUMP_REL32) => rel32_target(bytes, at),
        Some(&TWO_BYTE_OPCODE) => bytes
            .get(at + 1)
            .filter(|second| JCC_REL32.contains(*second))
            .and_then(|_| relative(bytes, at + JCC_OPERAND, at + JCC_REL32_LEN)),
        _ => None,
    };

    range
        .clone()
        .filter(|at| target(*at).is_some_and(|target| block.contains(&target))) // every byte: a decoder can lose step
        .count()
}

fn pointers_into(
    bytes: &[u8],
    kind: PeKind,
    base: usize,
    range: &Range<usize>,
    block: &Range<usize>,
) -> usize {
    range
        .clone()
        .step_by(kind.pointer_width())
        .filter_map(|at| read_pointer(bytes, at, kind).ok()?.checked_sub(base))
        .filter(|rva| block.contains(rva))
        .count()
}

fn operands_into(
    bytes: &[u8],
    base: u64,
    bits: u32,
    code: &[Range<usize>],
    block: &Range<usize>,
) -> usize {
    let inside = |address: u64| {
        address
            .checked_sub(base)
            .and_then(|rva| usize::try_from(rva).ok())
            .is_some_and(|rva| block.contains(&rva))
    };

    code.iter()
        .flat_map(|range| instructions(bytes, base, bits, range))
        .filter(|insn| !insn.is_invalid() && refers(insn, &inside))
        .count()
}

fn refers(insn: &Instruction, inside: &dyn Fn(u64) -> bool) -> bool {
    let operands = || (0..insn.op_count()).map(|operand| (operand, insn.op_kind(operand)));

    let memory =
        operands().any(|(_, kind)| kind == OpKind::Memory) && inside(insn.memory_displacement64()); // rip-relative: already the address
    let immediate = operands().any(|(operand, kind)| {
        let wide = matches!(
            kind,
            OpKind::Immediate32 | OpKind::Immediate32to64 | OpKind::Immediate64
        );
        wide && inside(insn.immediate(operand))
    });
    let short = is_near_immediate(insn) && insn.len() < REL32_LEN; // branches_into counts the rel32 ones
    let branch = short && inside(insn.near_branch_target());

    memory || immediate || branch
}

fn drop_sections(
    restored: &mut Vec<u8>,
    model: &PeModel,
    layout: &Layout,
    base: usize,
    code: &[Range<usize>],
    report: &mut PackerReport,
) -> bool {
    let program = 0..layout.payload();
    if !evacuate(
        restored,
        model,
        &program,
        &layout.block,
        MOVED_TABLES_SECTION,
    ) {
        report.failed_with(
            Part::PackerSections,
            "a table they hold had nowhere to move to",
        );
        return false;
    }

    let reach = Reach::of(restored, model, layout, base, code);
    if !reach.is_empty() {
        report.failed_with(Part::PackerSections, "code or data still leads into them");
        report.notes.push(reach.describe());
        return false;
    }

    let blocks = drop_relocation_blocks(restored, model, &layout.sections);
    if let Some((dropped, kept)) = blocks.filter(|(dropped, _)| *dropped > 0) {
        if kept == 0 {
            report.lost(Part::Relocations);
        }
        report.notes.push(match kept {
            0 => format!(
                "{dropped} relocation blocks dropped with vmp's sections, all for its own pages; the table lists none for the program"
            ),
            kept => format!(
                "{dropped} relocation blocks for vmp's own pages dropped, {kept} of the program's kept"
            ),
        });
    }

    let dropped = shed(restored, model, &layout.sections);
    if dropped > 0 {
        report.notes.push(format!(
            "{} KiB of vmp's own sections dropped from the file, their pages left mapped and empty",
            dropped / 1024
        ));
    }
    true
}

pub(crate) fn resource_apis_hooked(bytes: &[u8]) -> bool {
    const RESOURCE_APIS: [&str; 2] = ["LdrFindResource_U", "LdrAccessResource"];

    let hooked = |function: usize| {
        let jumps = bytes
            .get(function..function.saturating_add(REL32_LEN))
            .is_some_and(|code| code[0] == JUMP_REL32);
        jumps && rel32_target(bytes, function).is_none_or(|target| target >= bytes.len()) // resource protection hooks ntdll
    };

    RESOURCE_APIS
        .iter()
        .filter_map(|api| crate::pe::export_rva(bytes, api))
        .any(hooked)
}

pub(super) struct Vmprotect;

impl Packer for Vmprotect {
    fn unpack(&self, image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
        unpack(image, origin)
    }

    fn original_code(&self, image: &PeImage<'_>, _base: usize) -> Option<Vec<Range<usize>>> {
        original_code(image)
    }

    fn checks_debugger_directly(&self, image: &PeImage<'_>) -> bool {
        recognised(image) // direct syscalls
    }
}
