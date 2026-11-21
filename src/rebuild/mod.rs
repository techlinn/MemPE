mod diagnostics;
mod directories;
mod exceptions;
mod headers;
mod import_section;
mod inputs;
mod layout;
mod overlay;
mod sections;
mod source_image;

use std::borrow::Cow;
use std::ops::Range;
use std::path::Path;

use diagnostics::{
    absent_sections, count_write_execute_sections, entry_section_name, invalid_pdata_sections,
    never_decrypted_sections,
};
use directories::{
    ClearedDirectories, clear_bad_directories, clear_dynamic_base, repair_debug_directory,
};
use exceptions::{UnwindRanges, entry_unwind_covered, is_managed, repair_exception_directory};
use headers::{Finalized, finalize_output, write_core_header_fields};
use import_section::append_import_section;
pub(crate) use inputs::{EntryPointRva, RegionProtection};
pub(crate) use overlay::{OverlayStart, append_overlay, overlay_offset};
use sections::write_sections;
use source_image::{Protections, Resolution, Source, resolve_source_bytes};

use self::layout::{SectionLayout, align_up, align_up_u64, build_output_buffer, rva_to_file};
use crate::import_recovery::{
    ImportCounts, ImportPlan, build_iat_plan, build_plan, build_restored_plan,
};
use crate::pe::EXCEPTION_DIRECTORY;
use crate::pe::MAX_IMAGE_SIZE as MAX_OUTPUT_SIZE;
use crate::pe::PAGE_SIZE;
use crate::pe::bytes::read_u32;
use crate::pe::exports::ExportIndex;
use crate::pe::parse::parse_memory_image;
use crate::pe::process_memory::Process;
use crate::pe::{IAT_DIRECTORY, IMPORT_DIRECTORY, PeImage, PeKind, PeModel, SECTION_HEADER_SIZE};
use crate::pe::{
    IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA,
};
use crate::unpack::tables::tls_callbacks;
use crate::unpack::{FreshCopy, PackerFindings, PackerImports, PackerReport, Part, State};
use crate::{AppError, AppResult};

const HANDED_OVER: &str = "the first program instruction the packer handed control to; windows did not call it, so it is not confirmed";
const ENTERED_BY_WINDOWS: &str = "where windows entered the program when mempe started it";

pub(super) fn output_too_large(what: &str, size: usize) -> AppError {
    AppError::new(format!(
        "{what} needs {size} bytes, but mempe writes no file above {MAX_OUTPUT_SIZE} bytes (1 GiB)"
    ))
}

counters!(RebuildCounts(imports: ImportCounts) {
    cleared_directories,
    invalid_unwind_entries,
    imports_rebuilt,
    unemitted_imports,
    invalid_pdata_sections,
    renamed_sections,
    named_empty_sections,
    unreplaced_section_names,
    patched_section_headers,
    clamped_directories,
    tls_callbacks,
    repaired_debug_entries,
    never_decrypted_sections,
    absent_sections,
});

pub(crate) struct RebuiltFile {
    pub(crate) bytes: Vec<u8>,
    pub(crate) kind: PeKind,
    pub(crate) info: RebuildInfo,
    pub(crate) fresh: Option<FreshCopy>,
}

#[derive(Default)]
pub(crate) struct RebuildInfo {
    pub(crate) counts: RebuildCounts,
    pub(crate) is_dll: bool,
    pub(crate) sections: usize,
    pub(crate) salvaged_headers: bool,
    pub(crate) disk_headers_used: bool,
    pub(crate) declared_iat_slots: usize,
    pub(crate) managed: bool,
    pub(crate) entry_point: u32,
    pub(crate) entry_section: Option<String>,
    pub(crate) fixed_image_base: bool,
    pub(crate) notable_cleared_directories: Vec<String>,
    pub(crate) executable_flag_added: bool,
    pub(crate) unusable_observed_entry: Option<u32>,
    pub(crate) entry_unwind_covered: Option<bool>,
    pub(crate) write_execute_sections: usize,
    pub(crate) packer: Option<PackerReport>,
}

#[derive(Clone, Copy)]
pub(crate) struct DiskImage<'a> {
    pub(crate) headers: Option<&'a [u8]>,
    pub(crate) file: Option<&'a Path>,
}

#[derive(Clone, Copy)]
pub(crate) struct Captured<'a> {
    pub(crate) memory: &'a [u8],
    pub(crate) regions: &'a [RegionProtection],
    pub(crate) base: usize,
    pub(crate) page_flags: &'a [u8],
}

pub(crate) fn rebuild(
    captured: Captured<'_>,
    disk: DiskImage<'_>,
    process: Process<'_>,
    entry_point: Option<EntryPointRva>,
) -> AppResult<RebuiltFile> {
    let evidence = Protections {
        regions: captured.regions,
        page_flags: captured.page_flags,
    };
    let Resolution { source, fallback } =
        resolve_source_bytes(captured.memory, evidence, captured.base, disk, process)?;
    let build = |source| rebuild_with_fresh(source, captured, process.exports, entry_point);

    build(source).or_else(|error| {
        let Some(fallback) = fallback else {
            return Err(error);
        };

        let Ok(mut rebuilt) = fallback.source(evidence).and_then(build) else {
            return Err(error);
        };

        if let Some(report) = &mut rebuilt.info.packer {
            report
                .notes
                .push(format!("the unpacked image did not rebuild: {error}"));
        }
        Ok(rebuilt)
    })
}

fn rebuild_with_fresh(
    mut source: Source<'_>,
    captured: Captured<'_>,
    exports: &ExportIndex,
    entry_point: Option<EntryPointRva>,
) -> AppResult<RebuiltFile> {
    let fresh = source.fresh.take().map(|fresh| {
        let copy = Source {
            bytes: Cow::Owned(fresh.bytes),
            disk_headers_used: source.disk_headers_used,
            salvaged_headers: source.salvaged_headers,
            packer: source.packer.clone(),
            fresh: None,
            patched_sections: source.patched_sections,
        };
        (copy, fresh.changed, fresh.left_in_entry_section)
    });

    let rebuild = |source| rebuild_source(source, captured, exports, entry_point);

    let mut rebuilt = rebuild(source)?;
    match fresh.map(|(copy, changed, left)| (rebuild(copy), changed, left)) {
        Some((Ok(image), changed, left)) => {
            if let Some(report) = rebuilt.info.packer.as_mut().filter(|_| left > 0) {
                report.notes.push(format!(
                    "the fresh copy keeps the entry point's section as it ran ({left} changed bytes there were not reset)"
                ));
            }
            rebuilt.fresh = Some(FreshCopy {
                bytes: image.bytes,
                changed,
                left_in_entry_section: left,
            });
        }
        Some((Err(error), _, _)) => {
            if let Some(report) = &mut rebuilt.info.packer {
                report
                    .notes
                    .push(format!("the fresh copy did not rebuild: {error}"));
            }
        }
        None => {}
    }

    Ok(rebuilt)
}

// the packer's own records beat what launch mode saw, and windows entering the program beats a
// compiler signature; a disagreement with the signature is reported
fn choose_entry_point(
    entry_point: Option<EntryPointRva>,
    image: &PeImage<'_>,
    callbacks: &[usize],
    packer: Option<&mut PackerFindings>,
) -> Option<EntryPointRva> {
    let packer_entry = packer
        .as_ref()
        .and_then(|packer| packer.report.entry_state());
    let entry_point = entry_point
        .filter(|entry| match packer_entry {
            Some(State::Restored) => !entry.is_observed(),
            Some(_) => !entry.is_handed_over(),
            None => true,
        })
        .filter(|entry| {
            !entry.is_handed_over() || !callbacks.contains(&(entry.get() as usize)) // the packer ran a callback first
        });
    let (Some(entry), Some(findings)) = (entry_point, packer) else {
        return entry_point;
    };

    if entry.is_handed_over() {
        findings.report.inferred(Part::EntryPoint, HANDED_OVER);
    }

    if entry.is_observed()
        && packer_entry == Some(State::Inferred)
        && let Ok(inferred) = read_u32(image.bytes(), image.model().entry_point_offset)
        && inferred != entry.get()
    {
        findings.report.withdraw(Part::EntryPoint);
        findings
            .report
            .restored_with(Part::EntryPoint, ENTERED_BY_WINDOWS);
        findings.report.notes.push(format!(
            "windows entered the program at 0x{:08X}, not at the 0x{inferred:08X} its startup code pointed to; the address windows entered was used",
            entry.get()
        ));
    }

    entry_point
}

fn rebuild_source(
    source: Source<'_>,
    captured: Captured<'_>,
    exports: &ExportIndex,
    entry_point: Option<EntryPointRva>,
) -> AppResult<RebuiltFile> {
    let Captured {
        regions,
        base: observed_base,
        page_flags,
        ..
    } = captured;
    let Source {
        bytes: source,
        disk_headers_used,
        salvaged_headers,
        mut packer,
        patched_sections,
        ..
    } = source;

    let image = parse_memory_image(&source)
        .map_err(|error| AppError::new(format!("rebuilt PE headers are invalid: {error}")))?;
    let memory = image.bytes();
    let model = image.model();
    let callbacks = tls_callbacks(memory, model, observed_base);
    let entry_point = choose_entry_point(entry_point, &image, &callbacks, packer.as_mut());

    let restored_imports = packer
        .as_ref()
        .filter(|findings| findings.report.restored_anything())
        .map(|findings| &findings.imports);
    let packer_ranges = packer
        .as_ref()
        .map_or(&[][..], |findings| findings.packer_ranges.as_slice());
    let unpacked = restored_imports.is_some();
    let plan = plan_imports(
        &image,
        observed_base,
        exports,
        restored_imports,
        packer_ranges,
    );

    let rejected_restored_table = matches!(restored_imports, Some(PackerImports::Intact))
        && (plan.existing.is_empty() || plan.rejected_descriptors > 0);
    if rejected_restored_table && let Some(findings) = &mut packer {
        reject_restored_imports(&mut findings.report, !plan.existing.is_empty());
    }

    let (mut output, layouts, header_size) =
        build_output_buffer(model, memory, &plan.import_tables(model.kind))?;

    write_core_header_fields(&mut output, model, observed_base, header_size)?;

    let names = write_sections(&mut output, memory, &layouts)?;

    let mut repairs = apply_repairs(&mut output, model, &layouts, header_size)?;
    let ImportOutcome {
        plan: import_plan,
        written,
        unemitted,
    } = resolve_imports(&mut output, model, plan, &mut repairs, |rva| {
        rva_to_file(rva, &layouts, header_size)
    })?;

    let Finalized {
        entry_point: final_entry_point,
        executable_flag_added,
        unusable_observed_entry,
    } = finalize_output(&mut output, model, entry_point)?;

    let counts = RebuildCounts {
        cleared_directories: repairs.cleared.total,
        invalid_unwind_entries: repairs.invalid_unwind_entries,
        imports_rebuilt: if written { import_plan.recovered } else { 0 },
        unemitted_imports: unemitted,
        invalid_pdata_sections: invalid_pdata_sections(&output, model, &layouts, header_size),
        renamed_sections: names.renamed,
        named_empty_sections: names.named,
        unreplaced_section_names: names.unreplaced,
        patched_section_headers: patched_sections,
        clamped_directories: repairs.cleared.clamped,
        tls_callbacks: callbacks.len(),
        repaired_debug_entries: repairs.repaired_debug_entries,
        never_decrypted_sections: match unpacked {
            true => 0, // unpacked: write signal void
            false => never_decrypted_sections(memory, &layouts, page_flags),
        },
        absent_sections: absent_sections(memory, &layouts),
        imports: import_plan.counts,
    };

    Ok(RebuiltFile {
        kind: model.kind,
        fresh: None,
        info: RebuildInfo {
            counts,
            is_dll: model.is_dll,
            sections: model.sections.len().saturating_add(usize::from(written)),
            salvaged_headers: salvaged_headers || model.salvaged,
            disk_headers_used,
            declared_iat_slots: declared_iat_slots(&image, model),
            managed: is_managed(&output, model),
            entry_point: final_entry_point,
            entry_section: entry_section_name(&output, &layouts, final_entry_point),
            fixed_image_base: repairs.fixed_image_base,
            notable_cleared_directories: repairs.cleared.notable_names(),
            executable_flag_added,
            unusable_observed_entry,
            entry_unwind_covered: entry_unwind_covered(&repairs.unwind_ranges, final_entry_point),
            write_execute_sections: count_write_execute_sections(&layouts, regions),
            packer: packer.map(|findings| findings.report),
        },
        bytes: output,
    })
}

fn plan_imports(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    restored: Option<&PackerImports>,
    packer_ranges: &[Range<usize>],
) -> ImportPlan {
    match restored {
        Some(PackerImports::Intact) => {
            build_restored_plan(image, observed_base, exports, None, packer_ranges)
        }
        Some(PackerImports::Listed(modules)) => {
            build_restored_plan(image, observed_base, exports, Some(modules), packer_ranges)
        }
        Some(PackerImports::FilledIat { rva, size, names }) => build_iat_plan(
            image,
            observed_base,
            exports,
            (*rva, *size),
            names,
            packer_ranges,
        ),
        Some(PackerImports::Unknown) => {
            let mut plan = build_plan(image, observed_base, exports, packer_ranges);
            plan.keep_iat_directory = true;
            plan
        }
        None => build_plan(image, observed_base, exports, packer_ranges),
    }
}

struct DirectoryRepairs {
    cleared: ClearedDirectories,
    unwind_ranges: Option<UnwindRanges>,
    invalid_unwind_entries: usize,
    repaired_debug_entries: usize,
    fixed_image_base: bool,
}

fn apply_repairs(
    output: &mut [u8],
    model: &PeModel,
    layouts: &[SectionLayout<'_>],
    header_size: usize,
) -> AppResult<DirectoryRepairs> {
    let mut cleared = clear_bad_directories(output, model, layouts, header_size)?;
    let exception = repair_exception_directory(output, model, layouts, header_size)?;

    if exception.cleared {
        cleared.record(EXCEPTION_DIRECTORY);
    }

    let repaired_debug_entries = repair_debug_directory(output, model, layouts, header_size)?;
    let fixed_image_base = clear_dynamic_base(output, model)?;

    Ok(DirectoryRepairs {
        cleared,
        unwind_ranges: exception.ranges,
        invalid_unwind_entries: exception.invalid,
        repaired_debug_entries,
        fixed_image_base,
    })
}

struct ImportOutcome {
    plan: ImportPlan,
    written: bool,
    unemitted: usize,
}

fn resolve_imports(
    output: &mut Vec<u8>,
    model: &PeModel,
    plan: ImportPlan,
    repairs: &mut DirectoryRepairs,
    slot_offset: impl Fn(u32) -> Option<usize>,
) -> AppResult<ImportOutcome> {
    let orphaned = !plan.existing.is_empty() && model.directory(output, IMPORT_DIRECTORY).is_none();
    let rewrite = orphaned || plan.rejected_descriptors > 0;

    let (written, unemitted) = if plan.groups.is_empty() && !rewrite {
        (false, 0)
    } else if let Some(cleared) = append_import_section(output, model, &plan, slot_offset)? {
        for index in cleared {
            repairs.cleared.record(index);
        }
        (true, 0)
    } else {
        (false, plan.recovered)
    };

    if !written && plan.existing.is_empty() && model.clear_directory(output, IMPORT_DIRECTORY) {
        repairs.cleared.record(IMPORT_DIRECTORY);
    }

    Ok(ImportOutcome {
        written,
        unemitted: unemitted.saturating_add(plan.unrepresentable),
        plan,
    })
}

fn reject_restored_imports(report: &mut PackerReport, kept_some: bool) {
    match kept_some {
        true => report.partly_failed(
            Part::Imports,
            "descriptors the unpacker restored did not validate",
        ),
        false => {
            report.withdraw(Part::Imports);
            report.failed_with(
                Part::Imports,
                "the table the unpacker restored did not validate",
            );
        }
    }
}

fn declared_iat_slots(image: &PeImage<'_>, model: &PeModel) -> usize {
    let Some(directory) = image.directory(IAT_DIRECTORY) else {
        return 0;
    };

    directory.size() as usize / model.kind.pointer_width()
}
