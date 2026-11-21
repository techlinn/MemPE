mod disk_file;
mod file_names;
pub(crate) mod output_folder;
mod raw_regions;
mod summary;

use std::panic::AssertUnwindSafe;

use self::disk_file::{
    captured, crt_api_sets, packed_file, rebuild_with_disk_headers, with_overlay,
};
use self::file_names::{embedded_label, image_name, output_name, with_suffix};
use self::raw_regions::{push_embedded, push_raw_regions, push_region_embedded};
pub(crate) use self::summary::CaptureCounts;
use self::summary::artifact_info;
pub(crate) use self::summary::{DumpOutcome, DumpSummary, FileReport};
use crate::capture::{Capture, CapturedImage, FileBacking};
use crate::cli::ImageSelector;
use crate::dump::output_folder::{OutputFile, OutputFolder, WrittenFile, wants_fresh_copies};
use crate::pe::NTDLL;
use crate::pe::{self, ExportIndex, ExportStats, Process, ProcessMemory};
use crate::process::TargetProcess;
use crate::rebuild::EntryPointRva;
use crate::rebuild::{self, DiskImage, RebuiltFile};
use crate::unpack::PackerId;
use crate::{AppError, AppResult};

pub(crate) struct BuildFailure {
    pub(crate) name: String,
    pub(crate) base: usize,
    pub(crate) error: AppError,
}

struct FreshInfo {
    dump_name: String,
    base: usize,
    changed_bytes: usize,
}

pub(crate) struct BuiltDump<'a> {
    output: &'a mut OutputFolder,
    files: Vec<WrittenFile<FileReport>>,
    fresh: Vec<OutputFile<FreshInfo>>,
    failures: Vec<BuildFailure>,
    main_rebuilt: bool,
    dll_failures: usize,
    export_stats: ExportStats,
    counts: CaptureCounts,
    selected_images: Option<usize>,
}

impl BuiltDump<'_> {
    fn save(&mut self, file: OutputFile<FileReport>) -> bool {
        let (name, base) = (file.preferred_name.clone(), file.context.base);

        match self.output.write(file) {
            Ok(written) => self.files.push(written),
            Err(error) => {
                self.failures.push(BuildFailure { name, base, error });
                return false;
            }
        }

        true
    }

    pub(crate) fn finish(mut self) -> DumpOutcome {
        let summary = DumpSummary::from_artifacts(&self.files);

        let changes = self
            .fresh
            .iter()
            .map(|file| (file.context.dump_name.clone(), file.context.changed_bytes))
            .collect::<Vec<_>>();
        let wanted = match changes.is_empty() {
            true => Ok(false),
            false => wants_fresh_copies(&changes),
        };

        let mut fresh_copies = Vec::new();
        for file in self.fresh {
            let (name, base) = (file.preferred_name.clone(), file.context.base);
            let saved = match &wanted {
                Ok(false) => continue,
                Ok(true) => self.output.write(file).map(|written| written.path),
                Err(error) => Err(AppError::new(error.to_string())),
            };

            match saved {
                Ok(path) => fresh_copies.push(path),
                Err(error) => self.failures.push(BuildFailure { name, base, error }),
            }
        }

        DumpOutcome {
            artifacts: self.files,
            fresh_copies,
            failures: self.failures,
            summary,
            export_stats: self.export_stats,
            capture: self.counts,
            main_rebuilt: self.main_rebuilt,
            dll_failures: self.dll_failures,
            selected_images: self.selected_images,
            stopped_without_packer: false,
        }
    }
}

pub(crate) fn build<'a>(
    target: &TargetProcess,
    capture: Capture,
    entry_point: Option<EntryPointRva>,
    only: Option<&ImageSelector>,
    output: &'a mut OutputFolder,
) -> BuiltDump<'a> {
    let counts = CaptureCounts {
        executable_non_image_allocations: capture.executable_non_image_allocations,
        headerless_live_code: capture.headerless_live_code,
        unscanned_bytes: capture.unscanned_non_image_bytes,
        locked_bytes: capture.locked_non_image_bytes,
        skipped: capture.skipped,
        raw_bytes_skipped: capture.raw_bytes_skipped,
        hidden_rejected: capture.hidden_rejected,
        main_base_conflict: capture.main_base_conflict,
        unknown_protection_images: capture
            .images
            .iter()
            .filter(|image| !image.protection_unknown.is_empty())
            .count(),
        unconfirmed_backing: capture
            .images
            .iter()
            .filter(|image| image.backing == FileBacking::Unknown)
            .count(),
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
        &crt_api_sets(),
    );

    let memory = ProcessMemory::new(
        images
            .iter()
            .map(|image| (image.base, image.bytes.as_slice()))
            .chain(
                carve_regions
                    .iter()
                    .map(|region| (region.base, region.bytes.as_slice())),
            ),
    );
    let process = Process {
        exports: &exports,
        memory: &memory,
    };

    let mut report = empty_report(target, &images, exports.stats(), counts, output);

    let manual = entry_point.is_some_and(|entry| !entry.is_observed());
    if manual && !images.iter().any(|image| image.is_main) {
        report.failures.push(main_failure(
            target,
            "manual entry point requires a captured main image",
        ));

        return report;
    }

    if only.is_none() {
        push_region_embedded(&carve_regions, &mut report);
    }

    push_raw_regions(raw_regions, &mut report);

    let (selected, main_selected) =
        build_selected(target, &images, process, entry_point, only, &mut report);

    if manual && !main_selected {
        report.failures.push(main_failure(
            target,
            "-e applies to the main image, which --only left out",
        ));
    }

    mark_resource_protection(&images, &mut report);

    report.selected_images = only.map(|_| selected);
    report
}

fn build_selected(
    target: &TargetProcess,
    images: &[CapturedImage],
    process: Process<'_>,
    entry_point: Option<EntryPointRva>,
    only: Option<&ImageSelector>,
    report: &mut BuiltDump<'_>,
) -> (usize, bool) {
    let mut selected = 0usize;
    let mut main_selected = false;

    for image in images {
        if only.is_some_and(|want| !want.matches(image.base, image.name.as_deref())) {
            continue;
        }

        selected = selected.saturating_add(1);
        main_selected |= image.is_main;
        push_embedded(target, image, report);

        build_image(target, image, process, entry_point, report);
    }

    (selected, main_selected)
}

fn main_failure(target: &TargetProcess, reason: &str) -> BuildFailure {
    BuildFailure {
        name: target.name.clone(),
        base: target.main_module.as_ref().map_or(0, |module| module.base),
        error: AppError::new(reason),
    }
}

fn mark_resource_protection(images: &[CapturedImage], report: &mut BuiltDump<'_>) {
    if !resource_lookups_hooked(images) {
        return;
    }

    if let Some(main) = report.files.iter_mut().find(|file| file.context.is_main)
        && main
            .context
            .rebuild
            .packer
            .as_ref()
            .is_some_and(|packer| packer.packer == PackerId::VmProtect)
    {
        main.context.resource_protection = true;
    }
}

// wow64 maps two, and a clean copy may be mapped beside the hooked one
fn resource_lookups_hooked(images: &[CapturedImage]) -> bool {
    images
        .iter()
        .filter(|image| {
            image
                .name
                .as_deref()
                .is_some_and(|name| name.eq_ignore_ascii_case(NTDLL))
        })
        .any(|ntdll| crate::packers::resource_apis_hooked(&ntdll.bytes))
}

fn prepare_images(images: &mut [CapturedImage]) {
    images.sort_unstable_by_key(|image| (!image.is_main, image.base));

    for image in images {
        if image.name.is_none() {
            image.name = pe::embedded_module_name(&image.bytes);
        }
    }
}

fn empty_report<'a>(
    target: &TargetProcess,
    images: &[CapturedImage],
    export_stats: ExportStats,
    counts: CaptureCounts,
    output: &'a mut OutputFolder,
) -> BuiltDump<'a> {
    let captured_bases = images.iter().map(|image| image.base).collect::<Vec<_>>();
    let dll_failures = target
        .modules
        .iter()
        .filter(|module| {
            Some(module.base) != target.main_module.as_ref().map(|main| main.base)
                && !captured_bases.contains(&module.base)
        })
        .count();

    BuiltDump {
        output,
        files: Vec::with_capacity(images.len()),
        fresh: Vec::new(),
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
    image: &CapturedImage,
    process: Process<'_>,
    entry_point: Option<EntryPointRva>,
    report: &mut BuiltDump<'_>,
) {
    let image_entry_point = if image.is_main { entry_point } else { None };
    let (mut rebuilt, mut overlay) = match rebuild_image(image, process, image_entry_point) {
        Ok(rebuilt) => with_overlay(image, rebuilt),
        Err(error) => return record_failure(target, image, error, report),
    };

    let preferred_name = output_name(target, image, rebuilt.info.is_dll);
    let fresh_name = with_suffix(&preferred_name, ".fresh");
    if let Some(error) = overlay.fresh_dropped.take() {
        report.failures.push(BuildFailure {
            name: fresh_name.clone(),
            base: image.base,
            error,
        });
    }

    let fresh = rebuilt.fresh.take().map(|fresh| OutputFile {
        preferred_name: fresh_name,
        bytes: fresh.bytes,
        context: FreshInfo {
            dump_name: preferred_name.clone(),
            base: image.base,
            changed_bytes: fresh.changed,
        },
    });

    let saved = report.save(OutputFile {
        preferred_name,
        bytes: rebuilt.bytes,
        context: artifact_info(image, rebuilt.kind, rebuilt.info, &overlay),
    });

    report.main_rebuilt |= image.is_main && saved;
    report.fresh.extend(fresh.filter(|_| saved));
}

fn record_failure(
    target: &TargetProcess,
    image: &CapturedImage,
    error: AppError,
    report: &mut BuiltDump<'_>,
) {
    let name = match image.hidden && !image.is_main {
        true => "hidden PE".to_owned(),
        false => image_name(target, image),
    };

    if !image.is_main && !image.hidden {
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
    process: Process<'_>,
    entry_point: Option<EntryPointRva>,
) -> AppResult<RebuiltFile> {
    let attempt = || rebuild_unguarded(image, process, entry_point);
    std::panic::catch_unwind(AssertUnwindSafe(attempt)).unwrap_or_else(|payload| {
        let detail = payload
            .downcast_ref::<&str>()
            .map(|text| (*text).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        Err(AppError::new(format!(
            "mempe hit a bug rebuilding this image, so it was skipped: {detail}"
        )))
    })
}

fn rebuild_unguarded(
    image: &CapturedImage,
    process: Process<'_>,
    entry_point: Option<EntryPointRva>,
) -> AppResult<RebuiltFile> {
    if let Err(memory_error) = pe::parse::parse_memory_image(&image.bytes) {
        return rebuild_with_disk_headers(image, process, entry_point, memory_error);
    }

    rebuild::rebuild(
        captured(image),
        DiskImage {
            headers: None,
            file: packed_file(image),
        },
        process,
        entry_point,
    )
}
