mod imports;
mod layout;
mod mutation;
mod wiped;

use std::ops::Range;

use self::layout::Layout;
use self::wiped::Wiped;
use super::branches::{REL32_LEN, set_rel32_target};
use super::emu;
use super::entry::compiler_entry;
use super::tables::{
    CODE_SECTION, append, drop_relocation_blocks, evacuate, keep_unwind_within, next_section_rva,
    recover_directories, shed, table_references,
};
use super::{Origin, PackerFindings, PackerImports, PackerReport, Unpacked};
use crate::pe::image::write_u32;
use crate::pe::{PeImage, PeModel};

const NAME: &str = "VMProtect";
const CLEANED_CODE_SECTION: &[u8; 8] = b".vmpcode";
const MOVED_TABLES_SECTION: &[u8; 8] = b".vmptab\0";

pub(super) fn unpack(image: &PeImage<'_>, origin: &Origin<'_>) -> Option<Unpacked> {
    let model = image.model();
    let layout = Layout::of(image)?;
    let bits = model.kind().bits();
    let base = origin.base as u64;

    let mut report = PackerReport::new(NAME, None);
    let mut restored = image.bytes().to_vec();

    let returns_to = |site| emu::stub_return(image.bytes(), base, bits, site);
    let imports = |site| imports::is_stub(image.bytes(), origin, bits, site);
    let vm_code = mutation::Payload {
        range: base + layout.payload() as u64..base + image.bytes().len() as u64,
        returns_to: &returns_to,
        imports: &imports,
    };

    let demutated = restore_mutated(image, &mut restored, &layout.code, &vm_code, base);
    let sites: Vec<Range<usize>> = layout
        .code
        .iter()
        .cloned()
        .chain(demutated.code.clone())
        .collect();
    let (resolved, refused) = imports::resolve(&restored, bits, &layout, &sites, &vm_code, origin);

    let confirmed = !resolved.is_empty() || demutated.mutated > 0 || layout.signed;
    if !confirmed {
        let reason =
            "image (the layout looks like vmp, but nothing confirmed it, so it was left as it is)";
        return Some(Unpacked::detected_only(NAME, None, reason));
    }

    demutated.describe(&mut report);
    let imports = imports::rebuild(&mut restored, model, &resolved, origin.base);
    describe_imports(&mut report, imports.is_some(), resolved.len(), refused);

    recover_directories(
        &mut restored,
        model,
        origin.base,
        layout.payload(),
        &mut report,
    );
    drop_vm_unwind(&mut restored, model, &layout, &mut report);
    Wiped {
        model,
        layout: &layout,
        base: origin.base,
        moved_tables: MOVED_TABLES_SECTION,
    }
    .restore(&mut restored, &mut report);
    restore_entry(&mut restored, model, &layout, origin.base, &mut report)?;
    drop_sections(&mut restored, model, &layout, origin.base, &mut report);

    report
        .lost
        .push(match demutated.written < demutated.mutated {
            true => "virtualized code, and mutated code that could not be written back",
            false => "virtualized code",
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

#[derive(Default)]
struct Demutated {
    written: usize, // verified and aimed at from the original code
    mutated: usize, // functions that cleaned to whole code, aimed at or not
    code: Option<Range<usize>>,
}

impl Demutated {
    fn describe(&self, report: &mut PackerReport) {
        if self.mutated > 0 {
            report.notes.push(format!(
                "{} of {} mutated functions cleaned into .vmpcode, {} of them verified to behave as vmp's copy did and aimed at from the original code",
                self.mutated, self.mutated, self.written
            ));
        }
    }
}

fn restore_mutated(
    image: &PeImage<'_>,
    restored: &mut Vec<u8>,
    code: &[Range<usize>],
    vm_code: &mutation::Payload<'_>,
    base: u64,
) -> Demutated {
    let model = image.model();
    let bits = model.kind().bits();
    let Some(at) = next_section_rva(restored, model) else {
        return Demutated::default();
    };

    let relocated = mutation::reencode(image.bytes(), base, bits, code, vm_code, base + at as u64);
    let placed = !relocated.code.is_empty()
        && append(
            restored,
            model,
            CLEANED_CODE_SECTION,
            CODE_SECTION,
            &relocated.code,
        )
        .is_some();
    if !placed {
        return Demutated {
            mutated: relocated.recoverable,
            ..Demutated::default()
        };
    }

    let written = relocated
        .moved
        .iter()
        .filter(|moved| aim_at_clean_copy(image.bytes(), restored, moved, base, bits))
        .count();

    Demutated {
        written,
        mutated: relocated.recoverable,
        code: Some(at..at + relocated.code.len()),
    }
}

fn aim_at_clean_copy(
    captured: &[u8],
    restored: &mut [u8],
    moved: &mutation::Moved,
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
    let same = emu::same_behaviour(
        captured,
        restored,
        base,
        bits,
        site,
        &(0..0),
        emu::Agreement::Every,
    );
    if !same {
        restored[jump].copy_from_slice(&original);
    }
    same
}

fn describe_imports(report: &mut PackerReport, rebuilt: bool, resolved: usize, refused: usize) {
    match rebuilt {
        true => report.restored.push("imports"),
        false => report
            .unrestored
            .push("imports (the original table is left as junk)"),
    }

    if refused > 0 {
        report.unrestored.push(
            "some calls into vmp code (virtualized entries, or stubs with no single reading)",
        );
    }
    if resolved > 0 || refused > 0 {
        report.notes.push(format!(
            "{resolved} import call sites rebuilt, {refused} other calls into vmp code left as they are"
        ));
    }
}

fn drop_vm_unwind(
    restored: &mut [u8],
    model: &PeModel,
    layout: &Layout,
    report: &mut PackerReport,
) {
    let dropped = keep_unwind_within(restored, model, &layout.code).unwrap_or(0);
    if dropped > 0 {
        report.notes.push(format!(
            "{dropped} exception-table entries for vmp's own code dropped, so disassemblers skip its junk"
        ));
    }
}

fn restore_entry(
    restored: &mut [u8],
    model: &PeModel,
    layout: &Layout,
    base: usize,
    report: &mut PackerReport,
) -> Option<()> {
    let Some(entry) = compiler_entry(restored, model, &layout.code, base) else {
        report.unrestored.push(
            "original entry point (virtualized, or a hand-written entry with no runtime to recognise)",
        );
        return Some(());
    };

    let entry = u32::try_from(entry).ok()?;
    write_u32(restored, model.entry_point_offset, entry).ok()?;
    report.restored.push("original entry point");
    Some(())
}

fn drop_sections(
    restored: &mut Vec<u8>,
    model: &PeModel,
    layout: &Layout,
    base: usize,
    report: &mut PackerReport,
) {
    let program = 0..layout.payload();
    if !evacuate(
        restored,
        model,
        &program,
        &layout.block,
        MOVED_TABLES_SECTION,
    ) {
        report
            .unrestored
            .push("vmp's sections (a table they hold had nowhere to move to)");
        return;
    }

    let referenced = table_references(restored, model, base);
    let (pinned, unused): (Vec<_>, Vec<_>) = layout
        .sections
        .iter()
        .cloned()
        .partition(|section| referenced.iter().any(|rva| section.contains(rva)));
    if !pinned.is_empty() {
        report.unrestored.push(
            "some of vmp's sections (a table moved out of them still points at data they hold)",
        );
    }

    let blocks = drop_relocation_blocks(restored, model, &layout.sections); // a kept section's fixups are still vmp's own
    if let Some((dropped, kept)) = blocks.filter(|(dropped, _)| *dropped > 0) {
        report.notes.push(match kept {
            0 => format!(
                "{dropped} relocation blocks dropped, every one of them vmp's own pages: it applies the program's fixups itself and tables none, so the dump has no relocations to carry"
            ),
            kept => format!(
                "{dropped} relocation blocks for vmp's own pages dropped, {kept} of the program's kept"
            ),
        });
    }

    let dropped = shed(restored, model, &unused);
    if dropped > 0 {
        report.notes.push(format!(
            "{} KiB of vmp's own sections dropped from the file, their pages left mapped and empty",
            dropped / 1024
        ));
    }
}
