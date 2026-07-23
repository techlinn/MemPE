use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::memory::{Capture, CapturedImage};
use crate::output::{OutputFile, OutputPlan, WrittenFile};
use crate::pe::{self, ExportIndex, ExportStats, PeKind, RebuiltImage};
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
    pub(crate) ambiguous_imports: usize,
    pub(crate) hidden: bool,
    pub(crate) is_main: bool,
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
    pub(crate) ambiguous_imports: usize,
    pub(crate) invalid_unwind_entries: usize,
}

pub(crate) struct BuildReport {
    files: Vec<OutputFile<ArtifactInfo>>,
    failures: Vec<BuildFailure>,
    main_rebuilt: bool,
    dll_failures: usize,
    export_stats: ExportStats,
    private_executable_allocations: usize,
    hidden_private_images: usize,
}

pub(crate) struct DumpOutcome {
    pub(crate) artifacts: Vec<WrittenFile<ArtifactInfo>>,
    pub(crate) failures: Vec<BuildFailure>,
    pub(crate) summary: DumpSummary,
    pub(crate) export_stats: ExportStats,
    pub(crate) private_executable_allocations: usize,
    pub(crate) hidden_private_images: usize,
    main_rebuilt: bool,
    dll_failures: usize,
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
            private_executable_allocations: self.private_executable_allocations,
            hidden_private_images: self.hidden_private_images,
            main_rebuilt: self.main_rebuilt,
            dll_failures: self.dll_failures,
        })
    }
}

impl DumpOutcome {
    pub(crate) fn is_complete(&self) -> bool {
        self.main_rebuilt && self.dll_failures == 0
    }

    pub(crate) fn main_rebuilt(&self) -> bool {
        self.main_rebuilt
    }

    pub(crate) fn dll_failures(&self) -> usize {
        self.dll_failures
    }

    pub(crate) fn has_warnings(&self) -> bool {
        self.summary.unreadable_pages > 0
            || self.summary.cleared_directories > 0
            || self.summary.repaired_headers > 0
            || self.summary.disk_header_repairs > 0
            || self.summary.ambiguous_imports > 0
            || self.summary.invalid_unwind_entries > 0
            || self.export_stats.unresolved_forwarders > 0
            || !self.failures.is_empty()
            || self.private_executable_allocations > self.hidden_private_images
    }
}

impl DumpSummary {
    fn from_artifacts(artifacts: &[WrittenFile<ArtifactInfo>]) -> Self {
        let mut summary = Self::default();
        for artifact in artifacts {
            summary.add(&artifact.context);
        }
        summary
    }

    fn add(&mut self, info: &ArtifactInfo) {
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
        self.imports_rebuilt = self.imports_rebuilt.saturating_add(info.imports_rebuilt);
        self.ambiguous_imports = self
            .ambiguous_imports
            .saturating_add(info.ambiguous_imports);
        self.invalid_unwind_entries = self
            .invalid_unwind_entries
            .saturating_add(info.invalid_unwind_entries);
    }
}

pub(crate) fn build(target: &TargetProcess, capture: Capture) -> BuildReport {
    let private_executable_allocations = capture.private_executable_allocations;
    let hidden_private_images = capture.images.iter().filter(|image| image.hidden).count();
    let mut images = capture.images;
    prepare_images(&mut images);

    let exports = ExportIndex::build(
        images
            .iter()
            .map(|image| (image.base, image.bytes.as_slice(), image.name.as_deref())),
    );
    let export_stats = exports.stats();
    let mut report = empty_report(
        target,
        &images,
        export_stats,
        private_executable_allocations,
        hidden_private_images,
    );
    for image in images {
        build_image(target, image, &exports, &mut report);
    }
    report
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
    private_executable_allocations: usize,
    hidden_private_images: usize,
) -> BuildReport {
    let captured_bases = images.iter().map(|image| image.base).collect::<Vec<_>>();
    let dll_failures = target
        .modules
        .iter()
        .filter(|module| {
            module.base != target.main_module.base && !captured_bases.contains(&module.base)
        })
        .count();
    BuildReport {
        files: Vec::with_capacity(images.len()),
        failures: Vec::new(),
        main_rebuilt: false,
        dll_failures,
        export_stats,
        private_executable_allocations,
        hidden_private_images,
    }
}

fn build_image(
    target: &TargetProcess,
    image: CapturedImage,
    exports: &ExportIndex,
    report: &mut BuildReport,
) {
    let known_module = image.name.is_some();
    match rebuild_image(&image, exports) {
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
        ambiguous_imports: rebuilt.ambiguous_imports,
        hidden: image.hidden,
        is_main: image.is_main,
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

fn rebuild_image(image: &CapturedImage, exports: &ExportIndex) -> AppResult<RebuiltImage> {
    match pe::rebuild(&image.bytes, image.base, None, exports) {
        Ok(rebuilt) => Ok(rebuilt),
        Err(memory_error) => rebuild_with_disk_headers(image, exports, memory_error),
    }
}

fn rebuild_with_disk_headers(
    image: &CapturedImage,
    exports: &ExportIndex,
    memory_error: AppError,
) -> AppResult<RebuiltImage> {
    let Some(path) = &image.path else {
        return Err(memory_error);
    };
    let disk_headers = read_disk_headers(path).map_err(|disk_error| {
        AppError::new(format!(
            "{memory_error}; could not read disk headers from {}: {disk_error}",
            path.display()
        ))
    })?;
    pe::rebuild(&image.bytes, image.base, Some(&disk_headers), exports)
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

    use super::{ArtifactInfo, DumpSummary};
    use crate::output::WrittenFile;
    use crate::pe::PeKind;

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
                ambiguous_imports: 0,
                hidden,
                is_main,
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
