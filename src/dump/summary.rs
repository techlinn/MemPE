use std::collections::BTreeSet;
use std::path::PathBuf;

use super::BuildFailure;
use super::disk_file::OverlayOutcome;
use crate::capture::{CapturedImage, HiddenRejections, MainBaseConflict, SkippedImages};
use crate::dump::output_folder::WrittenFile;
use crate::pe::{ExportStats, PeKind};
use crate::rebuild::{RebuildCounts, RebuildInfo};
use crate::unpack::State;

pub(crate) struct FileReport {
    pub(crate) base: usize,
    pub(crate) kind: Option<PeKind>,
    pub(crate) rebuild: RebuildInfo,
    pub(crate) unreadable_pages: usize,
    pub(crate) resource_protection: bool,
    pub(crate) pages_measured: bool,
    pub(crate) resident_pages: usize,
    pub(crate) private_pages: usize,
    pub(crate) overlay_left: bool,
    pub(crate) overlay_unchecked: bool,
    pub(crate) unlinked: bool,
    pub(crate) path_mismatch: bool,
    pub(crate) role: ArtifactKind,
    pub(crate) hidden: bool,
    pub(crate) is_main: bool,
}

#[derive(Clone, Copy)]
pub(crate) enum ArtifactKind {
    Image,
    Embedded,
    RawRegion,
    Sidecar,
}

impl FileReport {
    // a module the loader lists that no packer touched: its gaps say nothing about the target
    pub(crate) fn is_plain_module(&self) -> bool {
        matches!(self.role, ArtifactKind::Image)
            && !self.is_main
            && !self.hidden
            && self.rebuild.packer.is_none()
    }

    pub(super) fn sidecar(base: usize) -> Self {
        Self::unbuilt(base, None, ArtifactKind::Sidecar)
    }

    pub(super) fn raw(base: usize, unreadable_pages: usize) -> Self {
        Self {
            unreadable_pages,
            ..Self::unbuilt(base, None, ArtifactKind::RawRegion)
        }
    }

    pub(super) fn embedded(base: usize, kind: PeKind) -> Self {
        Self::unbuilt(base, Some(kind), ArtifactKind::Embedded)
    }

    fn unbuilt(base: usize, kind: Option<PeKind>, role: ArtifactKind) -> Self {
        Self {
            base,
            kind,
            role,
            rebuild: RebuildInfo::default(),
            unreadable_pages: 0,
            resource_protection: false,
            pages_measured: false,
            resident_pages: 0,
            private_pages: 0,
            overlay_left: false,
            overlay_unchecked: false,
            unlinked: false,
            path_mismatch: false,
            hidden: false,
            is_main: false,
        }
    }
}

#[derive(Default)]
pub(crate) struct DumpSummary {
    pub(crate) counts: RebuildCounts,
    pub(crate) dlls: usize,
    pub(crate) other_images: usize,
    pub(crate) hidden_images: usize,
    pub(crate) unreadable_pages: usize,
    pub(crate) repaired_headers: usize,
    pub(crate) disk_header_repairs: usize,
    pub(crate) rebuilt_images: usize,
    pub(crate) fixed_image_bases: usize,
    pub(crate) notable_cleared_directories: BTreeSet<String>,
    pub(crate) executable_flags_added: usize,
    pub(crate) overlays_left: usize,
    pub(crate) overlays_unchecked: usize,
    pub(crate) unlinked_images: usize,
    pub(crate) path_mismatches: usize,
    pub(crate) partly_unpacked: usize,
    pub(crate) raw_region_unreadable_pages: usize,
    pub(crate) raw_regions: usize,
    pub(crate) embedded_pes: usize,
    pub(crate) resource_protection: usize,
}

pub(crate) struct CaptureCounts {
    pub(crate) executable_non_image_allocations: usize,
    pub(crate) headerless_live_code: Vec<usize>,
    pub(crate) unscanned_bytes: usize,
    pub(crate) locked_bytes: usize, // no access, and the snapshot would not lift it
    pub(crate) skipped: SkippedImages,
    pub(crate) raw_bytes_skipped: usize,
    pub(crate) hidden_rejected: HiddenRejections,
    pub(crate) main_base_conflict: Option<MainBaseConflict>,
    pub(crate) unknown_protection_images: usize,
    pub(crate) unconfirmed_backing: usize,
    pub(crate) hidden_non_image_images: usize,
    pub(crate) main_image_missing: bool,
}

pub(crate) struct DumpOutcome {
    pub(crate) artifacts: Vec<WrittenFile<FileReport>>,
    pub(crate) fresh_copies: Vec<PathBuf>,
    pub(crate) failures: Vec<BuildFailure>,
    pub(crate) summary: DumpSummary,
    pub(crate) export_stats: ExportStats,
    pub(crate) capture: CaptureCounts,
    pub(crate) main_rebuilt: bool,
    pub(crate) dll_failures: usize,
    pub(crate) selected_images: Option<usize>,
    pub(crate) stopped_without_packer: bool,
}

impl CaptureCounts {
    pub(crate) fn unmatched_non_image(&self) -> usize {
        self.executable_non_image_allocations
            .saturating_sub(self.hidden_non_image_images)
    }
}

impl DumpOutcome {
    pub(crate) fn is_complete(&self) -> bool {
        self.shortfalls().is_empty()
    }

    pub(crate) fn shortfalls(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if self.stopped_without_packer {
            lines.push(
                "no packer was recognised, so mempe stopped at the file's own entry point and a packed file is still packed".to_owned(),
            );
        }

        match self.selected_images {
            Some(0) => lines
                .push("no captured image matched the requested name or base address".to_owned()),
            Some(_) => {}
            None => {
                if self.capture.main_image_missing {
                    lines.push("the main image was not in the captured address space".to_owned());
                } else if !self.main_rebuilt {
                    lines.push("the main image was not written".to_owned());
                }

                if self.dll_failures > 0 {
                    lines.push(format!(
                        "{} loaded modules were not captured or not rebuilt",
                        self.dll_failures
                    ));
                }
            }
        }

        if !self.failures.is_empty() {
            lines.push(format!("{} files were not written", self.failures.len()));
        }

        if self.summary.partly_unpacked > 0 {
            lines.push(format!(
                "{} packed images were not fully restored",
                self.summary.partly_unpacked
            ));
        }

        if self.capture.skipped.total() > 0 {
            lines.push(format!(
                "{} images were skipped during capture",
                self.capture.skipped.total()
            ));
        }

        lines
    }
}

impl DumpSummary {
    pub(crate) fn from_artifacts<'a>(
        artifacts: impl IntoIterator<Item = &'a WrittenFile<FileReport>>,
    ) -> Self {
        let mut summary = Self::default();

        for artifact in artifacts {
            summary.add(&artifact.context);
        }

        summary
    }

    fn add(&mut self, info: &FileReport) {
        match info.role {
            ArtifactKind::Image => {}
            ArtifactKind::Sidecar => return,
            ArtifactKind::Embedded => {
                self.embedded_pes = self.embedded_pes.saturating_add(1);
                return;
            }
            ArtifactKind::RawRegion => {
                self.raw_regions = self.raw_regions.saturating_add(1);
                self.raw_region_unreadable_pages = self
                    .raw_region_unreadable_pages
                    .saturating_add(info.unreadable_pages);
                return;
            }
        }

        let rebuild = &info.rebuild;
        self.rebuilt_images = self.rebuilt_images.saturating_add(1);
        self.counts.add(&rebuild.counts);
        let listed = !info.is_main && !info.hidden;
        self.dlls = self
            .dlls
            .saturating_add(usize::from(listed && rebuild.is_dll));
        self.other_images = self
            .other_images
            .saturating_add(usize::from(listed && !rebuild.is_dll));
        self.hidden_images = self.hidden_images.saturating_add(usize::from(info.hidden));
        self.unreadable_pages = self.unreadable_pages.saturating_add(info.unreadable_pages);
        self.repaired_headers = self
            .repaired_headers
            .saturating_add(usize::from(rebuild.salvaged_headers));
        self.disk_header_repairs = self
            .disk_header_repairs
            .saturating_add(usize::from(rebuild.disk_headers_used));
        self.fixed_image_bases = self
            .fixed_image_bases
            .saturating_add(usize::from(rebuild.fixed_image_base));
        self.executable_flags_added = self
            .executable_flags_added
            .saturating_add(usize::from(rebuild.executable_flag_added));
        self.notable_cleared_directories
            .extend(rebuild.notable_cleared_directories.iter().cloned());
        self.overlays_left = self
            .overlays_left
            .saturating_add(usize::from(info.overlay_left));
        self.overlays_unchecked = self
            .overlays_unchecked
            .saturating_add(usize::from(info.overlay_unchecked));
        self.unlinked_images = self
            .unlinked_images
            .saturating_add(usize::from(info.unlinked));
        self.path_mismatches = self
            .path_mismatches
            .saturating_add(usize::from(info.path_mismatch));
        self.resource_protection = self
            .resource_protection
            .saturating_add(usize::from(info.resource_protection));

        if let Some(packer) = &rebuild.packer {
            self.partly_unpacked = self
                .partly_unpacked
                .saturating_add(usize::from(packer.has(State::Failed)));
        }
    }
}

pub(super) fn artifact_info(
    image: &CapturedImage,
    kind: PeKind,
    rebuild: RebuildInfo,
    overlay: &OverlayOutcome,
) -> FileReport {
    FileReport {
        base: image.base,
        kind: Some(kind),
        rebuild,
        unreadable_pages: image.unreadable_pages,
        resource_protection: false,
        pages_measured: !image.page_flags.is_empty(),
        resident_pages: image.resident_pages,
        private_pages: image.private_pages,
        overlay_left: overlay.left,
        overlay_unchecked: overlay.unchecked,
        unlinked: image.linked == Some(false) && !image.hidden,
        path_mismatch: image.path_mismatch,
        role: ArtifactKind::Image,
        hidden: image.hidden,
        is_main: image.is_main,
    }
}
