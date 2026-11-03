mod directories;
mod exception;
mod headers;
mod import_section;
mod observe;
mod overlay;
mod sections;
mod source;

use crate::pe::exports::ExportIndex;
use crate::pe::imports::{ImportPlan, build_plan, build_restored_plan};
use crate::pe::packers::PackerImports;
use crate::pe::parse::parse_memory_image;
use crate::pe::{
    EntryPointRva, IAT_DIRECTORY, IMPORT_DIRECTORY, PackerReport, PeImage, PeKind, PeModel,
    RegionEvidence, SectionModel,
};
use crate::{AppError, AppResult};
use directories::{
    ClearedDirectories, clear_bad_directories, clear_directory, clear_dynamic_base,
    repair_debug_directory,
};
use exception::{UnwindRanges, entry_unwind_covered, repair_exception_directory, unwind_layout};
use headers::{finalize_output, write_core_header_fields};
use import_section::{ImportSection, append_import_section};
use observe::{
    absent_sections, count_tls_callbacks, count_write_execute_sections, entry_section_name,
    invalid_pdata_sections, never_decrypted_sections,
};
use sections::{build_output_buffer, write_sections};
use source::{Source, Unpack, resolve_source_bytes};

pub(crate) use overlay::{append_overlay, overlay_offset};

const SECTION_HEADER_SIZE: usize = 40;
const MAX_OUTPUT_SIZE: usize = 1024 * 1024 * 1024;
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
const PAGE_SIZE: usize = 4 * 1024;

pub(crate) struct RebuiltImage {
    pub(crate) bytes: Vec<u8>,
    pub(crate) kind: PeKind,
    pub(crate) is_dll: bool,
    pub(crate) section_count: usize,
    pub(crate) salvaged_headers: bool,
    pub(crate) disk_headers_used: bool,
    pub(crate) cleared_directories: usize,
    pub(crate) invalid_unwind_entries: usize,
    pub(crate) imports_rebuilt: usize,
    pub(crate) unemitted_imports: usize,
    pub(crate) unresolved_delay: usize,
    pub(crate) unresolved_other_module: usize,
    pub(crate) unresolved_outside_image: usize,
    pub(crate) unresolved_unknown_stub: usize,
    pub(crate) unresolved_chain_exhausted: usize,
    pub(crate) slots_outside_data_sections: usize,
    pub(crate) recovered_attested: usize,
    pub(crate) recovered_scanned: usize,
    pub(crate) recovered_delayed: usize,
    pub(crate) recovered_inferred: usize,
    pub(crate) recovered_packer: usize,
    pub(crate) mixed_module_runs: usize,
    pub(crate) slots_with_call_sites: usize,
    pub(crate) ambiguous_imports: usize,
    pub(crate) aliased_names: usize,
    pub(crate) declared_iat_slots: usize,
    pub(crate) invalid_pdata_sections: usize,
    pub(crate) managed: bool,
    pub(crate) renamed_sections: usize,
    pub(crate) tls_callbacks: usize,
    pub(crate) entry_point: u32,
    pub(crate) entry_section: Option<String>,
    pub(crate) repaired_debug_entries: usize,
    pub(crate) fixed_image_base: bool,
    pub(crate) notable_cleared_directories: Vec<String>,
    pub(crate) executable_flag_added: bool,
    pub(crate) entry_unwind_covered: Option<bool>,
    pub(crate) write_execute_sections: usize,
    pub(crate) never_decrypted_sections: usize,
    pub(crate) absent_sections: usize,
    pub(crate) packer: Option<PackerReport>,
}

struct SectionLayout<'a> {
    model: &'a SectionModel,
    source_length: usize,
    raw_offset: usize,
    raw_size: usize,
}

pub(crate) fn rebuild(
    memory: &[u8],
    regions: &[RegionEvidence],
    observed_base: usize,
    disk_headers: Option<&[u8]>,
    exports: &ExportIndex,
    entry_point: Option<EntryPointRva>,
    page_flags: &[u8],
) -> AppResult<RebuiltImage> {
    let attempt = |unpack: Unpack| {
        let source = resolve_source_bytes(memory, regions, disk_headers, unpack)?;
        rebuild_source(
            source,
            regions,
            observed_base,
            exports,
            entry_point,
            page_flags,
        )
    };
    attempt(Unpack::Restore).or_else(|error| match attempt(Unpack::DetectOnly) {
        Ok(rebuilt) if rebuilt.packer.is_some() => Ok(rebuilt), // fall back to the packed image
        _ => Err(error),
    })
}

fn rebuild_source(
    source: Source<'_>,
    regions: &[RegionEvidence],
    observed_base: usize,
    exports: &ExportIndex,
    entry_point: Option<EntryPointRva>,
    page_flags: &[u8],
) -> AppResult<RebuiltImage> {
    let Source {
        bytes: source,
        disk_headers_used,
        packer,
    } = source;
    let image = parse_memory_image(&source)
        .map_err(|error| AppError::new(format!("rebuilt PE headers are invalid: {error}")))?;
    let memory = image.bytes();
    let model = image.model();
    let restored_imports = packer
        .as_ref()
        .filter(|findings| !findings.report.restored.is_empty())
        .map(|findings| &findings.imports);
    let unpacked = restored_imports.is_some();
    let plan = match restored_imports {
        Some(PackerImports::Intact) => build_restored_plan(&image, observed_base, exports, None),
        Some(PackerImports::Listed(modules)) => {
            build_restored_plan(&image, observed_base, exports, Some(modules))
        }
        Some(PackerImports::Unknown) | None => build_plan(&image, observed_base, exports),
    };
    let (mut output, layouts, header_size) =
        build_output_buffer(model, memory, !plan.groups.is_empty())?;

    write_core_header_fields(&mut output, model, observed_base, header_size)?;
    let renamed_sections = write_sections(&mut output, memory, &layouts)?;

    let mut repairs = apply_repairs(&mut output, model, &layouts, header_size)?;
    let ImportOutcome {
        plan: import_plan,
        written,
        unemitted,
    } = resolve_imports(&mut output, model, plan, &mut repairs)?;
    let (final_entry_point, executable_flag_added) =
        finalize_output(&mut output, model, entry_point)?;

    Ok(RebuiltImage {
        kind: model.kind,
        is_dll: model.is_dll,
        section_count: model.sections.len().saturating_add(usize::from(written)),
        salvaged_headers: model.salvaged,
        disk_headers_used,
        cleared_directories: repairs.cleared.total,
        notable_cleared_directories: repairs.cleared.notable_names(),
        invalid_unwind_entries: repairs.invalid_unwind_entries,
        imports_rebuilt: if written { import_plan.recovered } else { 0 },
        unemitted_imports: unemitted,
        unresolved_delay: import_plan.unresolved_delay,
        unresolved_other_module: import_plan.unresolved_other_module,
        unresolved_outside_image: import_plan.unresolved_outside_image,
        unresolved_unknown_stub: import_plan.unresolved_unknown_stub,
        unresolved_chain_exhausted: import_plan.unresolved_chain_exhausted,
        slots_outside_data_sections: import_plan.slots_outside_data_sections,
        recovered_attested: import_plan.recovered_attested,
        recovered_scanned: import_plan.recovered_scanned,
        recovered_delayed: import_plan.recovered_delayed,
        recovered_inferred: import_plan.recovered_inferred,
        recovered_packer: import_plan.recovered_packer,
        mixed_module_runs: import_plan.mixed_module_runs,
        slots_with_call_sites: import_plan.slots_with_call_sites,
        ambiguous_imports: import_plan.ambiguous,
        aliased_names: import_plan.aliased_names,
        declared_iat_slots: declared_iat_slots(&image, model),
        invalid_pdata_sections: invalid_pdata_sections(&output, model, &layouts, header_size),
        managed: unwind_layout(&output, model).is_managed(),
        renamed_sections,
        tls_callbacks: count_tls_callbacks(&image, observed_base),
        entry_point: final_entry_point,
        entry_section: entry_section_name(&layouts, final_entry_point),
        repaired_debug_entries: repairs.repaired_debug_entries,
        fixed_image_base: repairs.fixed_image_base,
        executable_flag_added,
        entry_unwind_covered: entry_unwind_covered(&repairs.unwind_ranges, final_entry_point),
        write_execute_sections: count_write_execute_sections(&layouts, regions),
        never_decrypted_sections: match unpacked {
            true => 0, // the unpacker rebuilt these bytes, so page writes say nothing about them
            false => never_decrypted_sections(memory, &layouts, page_flags),
        },
        absent_sections: absent_sections(memory, &layouts),
        packer: packer.map(|findings| findings.report),
        bytes: output,
    })
}

struct RepairStats {
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
) -> AppResult<RepairStats> {
    let cleared = clear_bad_directories(output, model, layouts, header_size)?;
    let exception = repair_exception_directory(output, model, layouts, header_size)?;
    let repaired_debug_entries = repair_debug_directory(output, model, layouts, header_size)?;
    let fixed_image_base = clear_dynamic_base(output, model)?;
    Ok(RepairStats {
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
    repairs: &mut RepairStats,
) -> AppResult<ImportOutcome> {
    let section = match plan.groups.is_empty() {
        true => ImportSection::NothingToWrite,
        false => append_import_section(output, model, &plan)?,
    };
    let (written, unemitted, cleared) = match section {
        ImportSection::Written { cleared } => (true, 0, cleared),
        ImportSection::NothingToWrite => (false, 0, Vec::new()),
        ImportSection::NoImportDirectory | ImportSection::NoRoomInHeaders => {
            (false, plan.recovered, Vec::new())
        }
    };
    let unemitted = unemitted.saturating_add(plan.unrepresentable);
    for index in cleared {
        repairs.cleared.record(index);
    }
    if !written && plan.existing.is_empty() {
        let extra = clear_directory(output, model, IMPORT_DIRECTORY)?;
        if extra > 0 {
            repairs.cleared.record(IMPORT_DIRECTORY);
        }
    }

    Ok(ImportOutcome {
        plan,
        written,
        unemitted,
    })
}

fn declared_iat_slots(image: &PeImage<'_>, model: &PeModel) -> usize {
    let Ok(Some(directory)) = image.directory(IAT_DIRECTORY) else {
        return 0;
    };
    directory.size() as usize / model.kind.pointer_width()
}

fn rva_to_file(rva: u32, layouts: &[SectionLayout<'_>], header_size: usize) -> Option<usize> {
    let rva = rva as usize;
    if rva < header_size {
        return Some(rva);
    }
    layouts.iter().find_map(|layout| {
        if layout.raw_size == 0 {
            return None;
        }
        let start = layout.model.virtual_address.get() as usize;
        let delta = rva.checked_sub(start)?;
        (delta < layout.source_length).then(|| layout.raw_offset.saturating_add(delta))
    })
}

fn align_up(value: usize, alignment: usize) -> AppResult<usize> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(AppError::new("PE alignment is invalid"));
    }
    value
        .checked_add(alignment - 1)
        .map(|result| result & !(alignment - 1))
        .ok_or_else(|| AppError::new("PE alignment overflowed"))
}

fn align_up_u64(value: u64, alignment: u64) -> AppResult<u64> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(AppError::new("PE alignment is invalid"));
    }
    value
        .checked_add(alignment - 1)
        .map(|result| result & !(alignment - 1))
        .ok_or_else(|| AppError::new("PE alignment overflowed"))
}
