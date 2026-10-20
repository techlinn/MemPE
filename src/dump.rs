use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::memory::{Capture, CapturedImage, RawRegion};
use crate::output::{OutputFile, OutputPlan, WrittenFile};
use crate::pe::{self, EntryPointRva, ExportIndex, ExportStats, PeKind, RebuiltImage};
use crate::process::TargetProcess;
use crate::{AppError, AppResult};

const MAX_DISK_HEADER_BYTES: u64 = 1024 * 1024;

pub(crate) struct ArtifactInfo {
    pub(crate) base: usize,
    pub(crate) kind: PeKind,
    pub(crate) sections: usize,
    pub(crate) unreadable_pages: usize,
    pub(crate) salvaged_headers: bool,
    pub(crate) disk_headers_used: bool,
    pub(crate) cleared_directories: usize,
    pub(crate) invalid_unwind_entries: usize,
    pub(crate) imports_rebuilt: usize,
    pub(crate) unemitted_imports: usize,
    pub(crate) unresolved_delay: usize,
    pub(crate) unresolved_outside_image: usize,
    pub(crate) unresolved_unknown_stub: usize,
    pub(crate) unresolved_chain_exhausted: usize,
    pub(crate) slots_outside_data_sections: usize,
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
    pub(crate) resident_pages: usize,
    pub(crate) private_pages: usize,
    pub(crate) unlinked: bool,
    pub(crate) path_mismatch: bool,
    pub(crate) embedded: bool,
    pub(crate) raw_region: bool,
    pub(crate) hidden: bool,
    pub(crate) is_main: bool,
    pub(crate) sidecar: bool,
}

impl ArtifactInfo {
    fn sidecar(base: usize) -> Self {
        let mut info = Self::embedded(base, PeKind::Pe32Plus);
        info.embedded = false;
        info.sidecar = true;
        info
    }

    fn raw(base: usize, unreadable_pages: usize) -> Self {
        let mut info = Self::embedded(base, PeKind::Pe32Plus);
        info.embedded = false;
        info.raw_region = true;
        info.unreadable_pages = unreadable_pages;
        info
    }

    fn embedded(base: usize, kind: PeKind) -> Self {
        Self {
            base,
            kind,
            sections: 0,
            unreadable_pages: 0,
            salvaged_headers: false,
            disk_headers_used: false,
            cleared_directories: 0,
            invalid_unwind_entries: 0,
            imports_rebuilt: 0,
            unemitted_imports: 0,
            aliased_names: 0,
            declared_iat_slots: 0,
            invalid_pdata_sections: 0,
            managed: false,
            unresolved_delay: 0,
            unresolved_outside_image: 0,
            unresolved_unknown_stub: 0,
            unresolved_chain_exhausted: 0,
            slots_outside_data_sections: 0,
            ambiguous_imports: 0,
            renamed_sections: 0,
            tls_callbacks: 0,
            entry_point: 0,
            entry_section: None,
            repaired_debug_entries: 0,
            fixed_image_base: false,
            notable_cleared_directories: Vec::new(),
            executable_flag_added: false,
            entry_unwind_covered: None,
            write_execute_sections: 0,
            never_decrypted_sections: 0,
            absent_sections: 0,
            resident_pages: 0,
            private_pages: 0,
            unlinked: false,
            path_mismatch: false,
            embedded: true,
            raw_region: false,
            hidden: false,
            is_main: false,
            sidecar: false,
        }
    }
}

pub(crate) struct BuildFailure {
    pub(crate) name: String,
    pub(crate) base: usize,
    pub(crate) error: AppError,
}

#[derive(Default)]
pub(crate) struct DumpSummary {
    pub(crate) dlls: usize,
    pub(crate) hidden_images: usize,
    pub(crate) unreadable_pages: usize,
    pub(crate) cleared_directories: usize,
    pub(crate) repaired_headers: usize,
    pub(crate) disk_header_repairs: usize,
    pub(crate) imports_rebuilt: usize,
    pub(crate) unemitted_imports: usize,
    pub(crate) unresolved_delay: usize,
    pub(crate) unresolved_outside_image: usize,
    pub(crate) unresolved_unknown_stub: usize,
    pub(crate) unresolved_chain_exhausted: usize,
    pub(crate) slots_outside_data_sections: usize,
    pub(crate) ambiguous_imports: usize,
    pub(crate) aliased_names: usize,
    pub(crate) invalid_pdata_sections: usize,
    pub(crate) rebuilt_images: usize,
    pub(crate) invalid_unwind_entries: usize,
    pub(crate) renamed_sections: usize,
    pub(crate) tls_callbacks: usize,
    pub(crate) repaired_debug_entries: usize,
    pub(crate) fixed_image_bases: usize,
    pub(crate) notable_cleared_directories: BTreeSet<String>,
    pub(crate) executable_flags_added: usize,
    pub(crate) resident_pages: usize,
    pub(crate) private_pages: usize,
    pub(crate) unlinked_images: usize,
    pub(crate) path_mismatches: usize,
    pub(crate) never_decrypted_sections: usize,
    pub(crate) absent_sections: usize,
    pub(crate) raw_region_unreadable_pages: usize,
    pub(crate) raw_regions: usize,
    pub(crate) embedded_pes: usize,
}

pub(crate) struct BuildReport {
    files: Vec<OutputFile<ArtifactInfo>>,
    failures: Vec<BuildFailure>,
    main_rebuilt: bool,
    dll_failures: usize,
    export_stats: ExportStats,
    counts: CaptureCounts,
    selected_images: Option<usize>,
}

struct CaptureCounts {
    executable_non_image_allocations: usize,
    unscanned_non_image_bytes: usize,
    images_skipped: usize,
    hidden_non_image_images: usize,
    main_image_missing: bool,
}

pub(crate) struct DumpOutcome {
    pub(crate) artifacts: Vec<WrittenFile<ArtifactInfo>>,
    pub(crate) failures: Vec<BuildFailure>,
    pub(crate) summary: DumpSummary,
    pub(crate) export_stats: ExportStats,
    pub(crate) executable_non_image_allocations: usize,
    pub(crate) unscanned_non_image_bytes: usize,
    pub(crate) images_skipped: usize,
    pub(crate) hidden_non_image_images: usize,
    pub(crate) main_rebuilt: bool,
    pub(crate) dll_failures: usize,
    pub(crate) main_image_missing: bool,
    pub(crate) selected_images: Option<usize>,
}

impl BuildReport {
    pub(crate) fn write(self, output: &OutputPlan) -> AppResult<DumpOutcome> {
        let artifacts = output.write_all(self.files)?;
        let summary = DumpSummary::from_artifacts(&artifacts);
        Ok(DumpOutcome {
            artifacts,
            failures: self.failures,
            summary,
            export_stats: self.export_stats,
            executable_non_image_allocations: self.counts.executable_non_image_allocations,
            unscanned_non_image_bytes: self.counts.unscanned_non_image_bytes,
            images_skipped: self.counts.images_skipped,
            hidden_non_image_images: self.counts.hidden_non_image_images,
            main_rebuilt: self.main_rebuilt,
            dll_failures: self.dll_failures,
            main_image_missing: self.counts.main_image_missing,
            selected_images: self.selected_images,
        })
    }
}

impl DumpOutcome {
    pub(crate) fn is_complete(&self) -> bool {
        match self.selected_images {
            Some(selected) => selected > 0 && self.failures.is_empty(),
            None => self.main_rebuilt && self.dll_failures == 0 && !self.main_image_missing,
        }
    }

    pub(crate) fn has_warnings(&self) -> bool {
        self.summary.unreadable_pages > 0
            || self.summary.cleared_directories > 0
            || self.summary.repaired_headers > 0
            || self.summary.disk_header_repairs > 0
            || self.summary.ambiguous_imports > 0
            || self.summary.unemitted_imports > 0
            || self.summary.unresolved_outside_image > 0
            || self.summary.unresolved_unknown_stub > 0
            || self.summary.unresolved_chain_exhausted > 0
            || self.summary.slots_outside_data_sections > 0
            || self.summary.invalid_unwind_entries > 0
            || self.summary.renamed_sections > 0
            || self.summary.repaired_debug_entries > 0
            || self.summary.fixed_image_bases > 0
            || self.summary.executable_flags_added > 0
            || !self.summary.notable_cleared_directories.is_empty()
            || self.summary.unlinked_images > 0
            || self.summary.path_mismatches > 0
            || self.summary.never_decrypted_sections > 0
            || self.summary.absent_sections > 0
            || self.summary.raw_region_unreadable_pages > 0
            || self.summary.raw_regions > 0
            || self.export_stats.unresolved_forwarders > 0
            || !self.failures.is_empty()
            || self.main_image_missing
            || self.executable_non_image_allocations > self.hidden_non_image_images
            || self.unscanned_non_image_bytes > 0
            || self.images_skipped > 0
            || self.summary.aliased_names > 0
            || self.summary.invalid_pdata_sections > 0
    }
}

impl DumpSummary {
    fn from_artifacts(artifacts: &[WrittenFile<ArtifactInfo>]) -> Self {
        let mut summary = Self::default();
        for artifact in artifacts.iter().filter(|entry| !entry.context.sidecar) {
            summary.add(&artifact.context);
        }
        summary
    }

    fn add_imports(&mut self, info: &ArtifactInfo) {
        self.rebuilt_images = self.rebuilt_images.saturating_add(1);
        self.imports_rebuilt = self.imports_rebuilt.saturating_add(info.imports_rebuilt);
        self.unemitted_imports = self
            .unemitted_imports
            .saturating_add(info.unemitted_imports);
        self.unresolved_delay = self.unresolved_delay.saturating_add(info.unresolved_delay);
        self.unresolved_outside_image = self
            .unresolved_outside_image
            .saturating_add(info.unresolved_outside_image);
        self.unresolved_unknown_stub = self
            .unresolved_unknown_stub
            .saturating_add(info.unresolved_unknown_stub);
        self.unresolved_chain_exhausted = self
            .unresolved_chain_exhausted
            .saturating_add(info.unresolved_chain_exhausted);
        self.slots_outside_data_sections = self
            .slots_outside_data_sections
            .saturating_add(info.slots_outside_data_sections);
        self.ambiguous_imports = self
            .ambiguous_imports
            .saturating_add(info.ambiguous_imports);
        self.aliased_names = self.aliased_names.saturating_add(info.aliased_names);
        self.invalid_pdata_sections = self
            .invalid_pdata_sections
            .saturating_add(info.invalid_pdata_sections);
    }

    fn add(&mut self, info: &ArtifactInfo) {
        if info.raw_region {
            self.raw_regions = self.raw_regions.saturating_add(1);
            self.raw_region_unreadable_pages = self
                .raw_region_unreadable_pages
                .saturating_add(info.unreadable_pages);
            return;
        }
        if info.embedded {
            self.embedded_pes = self.embedded_pes.saturating_add(1);
            return;
        }
        self.add_imports(info);
        self.dlls = self.dlls.saturating_add(usize::from(!info.is_main));
        self.hidden_images = self.hidden_images.saturating_add(usize::from(info.hidden));
        self.unreadable_pages = self.unreadable_pages.saturating_add(info.unreadable_pages);
        self.cleared_directories = self
            .cleared_directories
            .saturating_add(info.cleared_directories);
        self.repaired_headers = self
            .repaired_headers
            .saturating_add(usize::from(info.salvaged_headers));
        self.disk_header_repairs = self
            .disk_header_repairs
            .saturating_add(usize::from(info.disk_headers_used));
        self.invalid_unwind_entries = self
            .invalid_unwind_entries
            .saturating_add(info.invalid_unwind_entries);
        self.renamed_sections = self.renamed_sections.saturating_add(info.renamed_sections);
        self.tls_callbacks = self.tls_callbacks.saturating_add(info.tls_callbacks);
        self.repaired_debug_entries = self
            .repaired_debug_entries
            .saturating_add(info.repaired_debug_entries);
        self.fixed_image_bases = self
            .fixed_image_bases
            .saturating_add(usize::from(info.fixed_image_base));
        self.executable_flags_added = self
            .executable_flags_added
            .saturating_add(usize::from(info.executable_flag_added));
        self.notable_cleared_directories
            .extend(info.notable_cleared_directories.iter().cloned());
        self.resident_pages = self.resident_pages.saturating_add(info.resident_pages);
        self.private_pages = self.private_pages.saturating_add(info.private_pages);
        self.unlinked_images = self
            .unlinked_images
            .saturating_add(usize::from(info.unlinked));
        self.path_mismatches = self
            .path_mismatches
            .saturating_add(usize::from(info.path_mismatch));
        self.never_decrypted_sections = self
            .never_decrypted_sections
            .saturating_add(info.never_decrypted_sections);
        self.absent_sections = self.absent_sections.saturating_add(info.absent_sections);
    }
}

fn image_matches(image: &CapturedImage, want: &str) -> bool {
    if let Some(text) = want.strip_prefix("0x").or_else(|| want.strip_prefix("0X"))
        && let Ok(base) = usize::from_str_radix(text, 16)
    {
        return image.base == base;
    }
    image
        .name
        .as_deref()
        .is_some_and(|name| name.eq_ignore_ascii_case(want))
}

pub(crate) fn build(
    target: &TargetProcess,
    capture: Capture,
    entry_point: Option<EntryPointRva>,
    only: Option<&str>,
) -> BuildReport {
    let counts = CaptureCounts {
        executable_non_image_allocations: capture.executable_non_image_allocations,
        unscanned_non_image_bytes: capture.unscanned_non_image_bytes,
        images_skipped: capture.images_skipped,
        hidden_non_image_images: capture.images.iter().filter(|image| image.hidden).count(),
        main_image_missing: capture.main_image_missing,
    };
    let carve_regions = capture.carve_regions;
    let raw_regions = capture.raw_regions;
    let mut images = capture.images;
    prepare_images(&mut images);

    let exports = ExportIndex::build(
        images
            .iter()
            .map(|image| (image.base, image.bytes.as_slice(), image.name.as_deref())),
    );
    let export_stats = exports.stats();
    let mut report = empty_report(target, &images, export_stats, counts);
    if entry_point.is_some() && !images.iter().any(|image| image.is_main) {
        report.failures.push(BuildFailure {
            name: target.name.clone(),
            base: target.main_module.as_ref().map_or(0, |module| module.base),
            error: AppError::new("manual entry point requires a captured main image"),
        });
        return report;
    }
    if only.is_none() {
        push_region_embedded(&carve_regions, &mut report);
    }
    push_raw_regions(&raw_regions, &mut report);
    let mut selected = 0usize;
    for image in images {
        if only.is_some_and(|want| !image_matches(&image, want)) {
            continue;
        }
        selected = selected.saturating_add(1);
        push_embedded(target, &image, &mut report);
        let validates_manual_entry_point = image.is_main && entry_point.is_some();
        build_image(target, image, &exports, entry_point, &mut report);
        if validates_manual_entry_point && !report.main_rebuilt {
            break;
        }
    }
    report.selected_images = only.map(|_| selected);
    report
}

fn push_region_embedded(regions: &[RawRegion], report: &mut BuildReport) {
    for region in regions {
        for (index, embedded) in pe::carve_embedded(&region.bytes).into_iter().enumerate() {
            let Some(bytes) = copy_range(&region.bytes, embedded.offset, embedded.length) else {
                continue;
            };
            report.files.push(OutputFile {
                preferred_name: format!(
                    "region-{:016X}.embed{}.{}",
                    region.base,
                    index.saturating_add(1),
                    embedded.extension
                ),
                bytes,
                context: ArtifactInfo::embedded(
                    region.base.saturating_add(embedded.offset),
                    embedded.kind,
                ),
            });
        }
    }
}

fn push_raw_regions(regions: &[RawRegion], report: &mut BuildReport) {
    for region in regions {
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(region.bytes.len()).is_err() {
            continue;
        }
        bytes.extend_from_slice(&region.bytes);
        let stem = format!("region.{:016X}.{:X}", region.base, bytes.len());
        let notes = region_notes(region, bytes.len());
        report.files.push(OutputFile {
            preferred_name: format!("{stem}.raw"),
            bytes,
            context: ArtifactInfo::raw(region.base, region.unreadable_pages),
        });
        report.files.push(OutputFile {
            preferred_name: format!("{stem}.txt"),
            bytes: notes.into_bytes(),
            context: ArtifactInfo::sidecar(region.base),
        });
    }
}

fn region_notes(region: &RawRegion, written: usize) -> String {
    format!(
        "load address        0x{:016X}\n\
         allocation base     0x{:016X}\n\
         bytes written       0x{written:X} ({written} bytes)\n\
         committed           0x{:X} ({} bytes)\n\
         protections         0x{:08X}, the union across every committed page\n\
         any page executable {}\n\
         unreadable          {} pages, zero-filled\n\
         \n\
         These are raw bytes with no PE structure. mempe does not invent a header\n\
         for them. Point a disassembler at the load address above. Protections are\n\
         a union, so individual pages inside this range may be less permissive.\n",
        region.base,
        region.base,
        region.committed,
        region.committed,
        region.protections,
        if region.executable { "yes" } else { "no" },
        region.unreadable_pages,
    )
}

fn push_embedded(target: &TargetProcess, image: &CapturedImage, report: &mut BuildReport) {
    let label = embedded_label(target, image);
    for (index, embedded) in pe::carve_embedded(&image.bytes).into_iter().enumerate() {
        let Some(bytes) = copy_range(&image.bytes, embedded.offset, embedded.length) else {
            continue;
        };
        report.files.push(OutputFile {
            preferred_name: format!(
                "{label}.embed{}.{}",
                index.saturating_add(1),
                embedded.extension
            ),
            bytes,
            context: ArtifactInfo::embedded(
                image.base.saturating_add(embedded.offset),
                embedded.kind,
            ),
        });
    }
}

fn embedded_label(target: &TargetProcess, image: &CapturedImage) -> String {
    let name = if image.is_main {
        target.name.as_str()
    } else if let Some(name) = &image.name {
        name.as_str()
    } else {
        return format!("module-{:016X}", image.base);
    };
    Path::new(name)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or(name)
        .to_owned()
}

fn copy_range(bytes: &[u8], offset: usize, length: usize) -> Option<Vec<u8>> {
    let slice = bytes.get(offset..offset.checked_add(length)?)?;
    let mut copy = Vec::new();
    copy.try_reserve_exact(slice.len()).ok()?;
    copy.extend_from_slice(slice);
    Some(copy)
}

fn prepare_images(images: &mut [CapturedImage]) {
    images.sort_unstable_by_key(|image| (!image.is_main, image.base));
    for image in images {
        if image.name.is_none() {
            image.name = pe::embedded_module_name(&image.bytes);
        }
    }
}

fn empty_report(
    target: &TargetProcess,
    images: &[CapturedImage],
    export_stats: ExportStats,
    counts: CaptureCounts,
) -> BuildReport {
    let captured_bases = images.iter().map(|image| image.base).collect::<Vec<_>>();
    let dll_failures = target
        .modules
        .iter()
        .filter(|module| {
            Some(module.base) != target.main_module.as_ref().map(|main| main.base)
                && !captured_bases.contains(&module.base)
        })
        .count();
    BuildReport {
        files: Vec::with_capacity(images.len()),
        failures: Vec::new(),
        main_rebuilt: false,
        dll_failures,
        export_stats,
        counts,
        selected_images: None,
    }
}

fn build_image(
    target: &TargetProcess,
    image: CapturedImage,
    exports: &ExportIndex,
    entry_point: Option<EntryPointRva>,
    report: &mut BuildReport,
) {
    let known_module = image.name.is_some();
    let image_entry_point = if image.is_main { entry_point } else { None };
    match rebuild_image(&image, exports, image_entry_point) {
        Ok(rebuilt) if should_write(&image, &rebuilt, known_module) => {
            report.main_rebuilt |= image.is_main;
            let preferred_name = output_name(target, &image, &rebuilt);
            let context = artifact_info(&image, &rebuilt);
            report.files.push(OutputFile {
                preferred_name,
                bytes: rebuilt.bytes,
                context,
            });
        }
        Ok(_) => {}
        Err(error) => record_failure(target, &image, known_module, error, report),
    }
}

fn should_write(image: &CapturedImage, rebuilt: &RebuiltImage, known_module: bool) -> bool {
    image.is_main || image.hidden || rebuilt.is_dll || known_module
}

fn artifact_info(image: &CapturedImage, rebuilt: &RebuiltImage) -> ArtifactInfo {
    ArtifactInfo {
        base: image.base,
        kind: rebuilt.kind,
        sections: rebuilt.section_count,
        unreadable_pages: image.unreadable_pages,
        salvaged_headers: rebuilt.salvaged_headers,
        disk_headers_used: rebuilt.disk_headers_used,
        cleared_directories: rebuilt.cleared_directories,
        invalid_unwind_entries: rebuilt.invalid_unwind_entries,
        imports_rebuilt: rebuilt.imports_rebuilt,
        unemitted_imports: rebuilt.unemitted_imports,
        aliased_names: rebuilt.aliased_names,
        declared_iat_slots: rebuilt.declared_iat_slots,
        invalid_pdata_sections: rebuilt.invalid_pdata_sections,
        managed: rebuilt.managed,
        unresolved_delay: rebuilt.unresolved_delay,
        unresolved_outside_image: rebuilt.unresolved_outside_image,
        unresolved_unknown_stub: rebuilt.unresolved_unknown_stub,
        unresolved_chain_exhausted: rebuilt.unresolved_chain_exhausted,
        slots_outside_data_sections: rebuilt.slots_outside_data_sections,
        ambiguous_imports: rebuilt.ambiguous_imports,
        renamed_sections: rebuilt.renamed_sections,
        tls_callbacks: rebuilt.tls_callbacks,
        entry_point: rebuilt.entry_point,
        entry_section: rebuilt.entry_section.clone(),
        repaired_debug_entries: rebuilt.repaired_debug_entries,
        fixed_image_base: rebuilt.fixed_image_base,
        notable_cleared_directories: rebuilt.notable_cleared_directories.clone(),
        executable_flag_added: rebuilt.executable_flag_added,
        entry_unwind_covered: rebuilt.entry_unwind_covered,
        write_execute_sections: rebuilt.write_execute_sections,
        never_decrypted_sections: rebuilt.never_decrypted_sections,
        absent_sections: rebuilt.absent_sections,
        resident_pages: image.resident_pages,
        private_pages: image.private_pages,
        unlinked: !image.linked && !image.hidden,
        path_mismatch: image.path_mismatch,
        raw_region: false,
        embedded: false,
        hidden: image.hidden,
        is_main: image.is_main,
        sidecar: false,
    }
}

fn record_failure(
    target: &TargetProcess,
    image: &CapturedImage,
    known_module: bool,
    error: AppError,
    report: &mut BuildReport,
) {
    let name = if image.is_main {
        target.name.clone()
    } else if image.hidden {
        "hidden PE".to_owned()
    } else if known_module {
        image
            .name
            .clone()
            .unwrap_or_else(|| "unknown.dll".to_owned())
    } else {
        return;
    };
    if known_module && !image.is_main && !image.hidden {
        report.dll_failures = report.dll_failures.saturating_add(1);
    }
    report.failures.push(BuildFailure {
        name,
        base: image.base,
        error,
    });
}

fn rebuild_image(
    image: &CapturedImage,
    exports: &ExportIndex,
    entry_point: Option<EntryPointRva>,
) -> AppResult<RebuiltImage> {
    match pe::rebuild(
        &image.bytes,
        &image.regions,
        image.base,
        None,
        exports,
        entry_point,
        &image.page_flags,
    ) {
        Ok(rebuilt) => Ok(rebuilt),
        Err(memory_error) => rebuild_with_disk_headers(image, exports, entry_point, memory_error),
    }
}

fn rebuild_with_disk_headers(
    image: &CapturedImage,
    exports: &ExportIndex,
    entry_point: Option<EntryPointRva>,
    memory_error: AppError,
) -> AppResult<RebuiltImage> {
    let Some(path) = &image.path else {
        return Err(memory_error);
    };
    if !image.image_backed {
        return Err(AppError::new(format!(
            "{memory_error}; refusing disk headers from {}: the memory at this base is no longer image-backed",
            path.display()
        )));
    }
    if image.path_mismatch {
        return Err(AppError::new(format!(
            "{memory_error}; refusing disk headers from {}: a different file is mapped at this base",
            path.display()
        )));
    }
    let disk_headers = read_disk_headers(path).map_err(|disk_error| {
        AppError::new(format!(
            "{memory_error}; could not read disk headers from {}: {disk_error}",
            path.display()
        ))
    })?;
    pe::rebuild(
        &image.bytes,
        &image.regions,
        image.base,
        Some(&disk_headers),
        exports,
        entry_point,
        &image.page_flags,
    )
}

fn read_disk_headers(path: &Path) -> AppResult<Vec<u8>> {
    let file = File::open(path)
        .map_err(|error| AppError::new(format!("cannot open {}: {error}", path.display())))?;
    let mut bytes = Vec::with_capacity(MAX_DISK_HEADER_BYTES as usize);
    file.take(MAX_DISK_HEADER_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|error| AppError::new(format!("cannot read {}: {error}", path.display())))?;
    Ok(bytes)
}

fn output_name(target: &TargetProcess, image: &CapturedImage, rebuilt: &RebuiltImage) -> String {
    if image.is_main {
        return with_extension(&target.name, "exe");
    }
    let fallback = format!("module-{:016X}.dll", image.base);
    let name = image.name.as_deref().unwrap_or(&fallback);
    if rebuilt.is_dll {
        with_extension(name, "dll")
    } else {
        with_extension(name, "exe")
    }
}

fn with_extension(name: &str, extension: &str) -> String {
    let mut path = PathBuf::from(name);
    path.set_extension(extension);
    path.file_name()
        .and_then(|value| value.to_str())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("dump.{extension}"))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{ArtifactInfo, DumpOutcome, DumpSummary};
    use crate::output::WrittenFile;
    use crate::pe::{ExportStats, PeKind};

    fn outcome(selected_images: Option<usize>, main_rebuilt: bool) -> DumpOutcome {
        DumpOutcome {
            artifacts: Vec::new(),
            failures: Vec::new(),
            summary: DumpSummary::default(),
            export_stats: ExportStats::default(),
            executable_non_image_allocations: 0,
            unscanned_non_image_bytes: 0,
            images_skipped: 0,
            hidden_non_image_images: 0,
            main_rebuilt,
            dll_failures: 0,
            main_image_missing: false,
            selected_images,
        }
    }

    #[test]
    fn a_filtered_dump_is_complete_only_when_the_filter_matched_something() {
        assert!(!outcome(Some(0), false).is_complete());
        assert!(outcome(Some(1), false).is_complete());
        assert!(!outcome(None, false).is_complete());
        assert!(outcome(None, true).is_complete());
    }

    fn artifact(is_main: bool, hidden: bool, imports: usize) -> WrittenFile<ArtifactInfo> {
        WrittenFile {
            path: PathBuf::new(),
            context: ArtifactInfo {
                base: 0,
                kind: PeKind::Pe32Plus,
                sections: 1,
                unreadable_pages: 2,
                salvaged_headers: false,
                disk_headers_used: false,
                cleared_directories: 1,
                invalid_unwind_entries: 0,
                imports_rebuilt: imports,
                unemitted_imports: 0,
                aliased_names: 0,
                declared_iat_slots: 0,
                invalid_pdata_sections: 0,
                managed: false,
                unresolved_delay: 0,
                unresolved_outside_image: 0,
                unresolved_unknown_stub: 0,
                unresolved_chain_exhausted: 0,
                slots_outside_data_sections: 0,
                ambiguous_imports: 0,
                renamed_sections: 1,
                tls_callbacks: 2,
                entry_point: 0x1000,
                entry_section: None,
                repaired_debug_entries: 1,
                fixed_image_base: true,
                notable_cleared_directories: Vec::new(),
                executable_flag_added: false,
                entry_unwind_covered: None,
                write_execute_sections: 0,
                never_decrypted_sections: 0,
                absent_sections: 0,
                resident_pages: 8,
                private_pages: 3,
                unlinked: false,
                path_mismatch: false,
                embedded: false,
                raw_region: false,
                hidden,
                is_main,
                sidecar: false,
            },
        }
    }

    #[test]
    fn summarizes_artifacts_without_parallel_lists() {
        let artifacts = [artifact(true, false, 2), artifact(false, true, 3)];

        let summary = DumpSummary::from_artifacts(&artifacts);

        assert_eq!(summary.dlls, 1);
        assert_eq!(summary.hidden_images, 1);
        assert_eq!(summary.unreadable_pages, 4);
        assert_eq!(summary.cleared_directories, 2);
        assert_eq!(summary.imports_rebuilt, 5);
    }
}
