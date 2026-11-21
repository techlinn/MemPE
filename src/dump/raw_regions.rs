use super::embedded_label;
use super::{BuildFailure, BuiltDump, FileReport};
use crate::AppError;
use crate::capture::{CapturedImage, RawRegion};
use crate::dump::output_folder::OutputFile;
use crate::pe::{self, CarveResult, CarveSource};
use crate::process::TargetProcess;

pub(super) fn push_region_embedded(regions: &[RawRegion], report: &mut BuiltDump<'_>) {
    for region in regions {
        let label = format!("region-{:016X}", region.base);
        save_embedded(
            &region.bytes,
            region.base,
            CarveSource::Buffer,
            &label,
            report,
        );
    }
}

pub(super) fn push_raw_regions(regions: Vec<RawRegion>, report: &mut BuiltDump<'_>) {
    for region in regions {
        let stem = format!("region.{:016X}.{:X}", region.base, region.bytes.len());
        let notes = region_notes(&region, region.bytes.len());
        let saved = report.save(OutputFile {
            preferred_name: format!("{stem}.raw"),
            bytes: region.bytes,
            context: FileReport::raw(region.base, region.unreadable_pages),
        });
        if !saved {
            continue;
        }

        report.save(OutputFile {
            preferred_name: format!("{stem}.txt"),
            bytes: notes.into_bytes(),
            context: FileReport::sidecar(region.base),
        });
    }
}

pub(super) fn region_notes(region: &RawRegion, written: usize) -> String {
    format!(
        "load address        0x{:016X}\n\
         allocation base     0x{:016X}\n\
         bytes written       0x{written:X} ({written} bytes)\n\
         committed           0x{committed:X} ({committed} bytes)\n\
         protections         0x{:08X}, the union across every committed page\n\
         any page executable {}\n\
         unreadable          {} pages, zero-filled\n\
         \n\
         These are raw bytes with no PE structure. mempe does not invent a header\n\
         for them. Point a disassembler at the load address above. Protections are\n\
         a union, so individual pages inside this range may be less permissive.\n",
        region.base,
        region.allocation_base,
        region.protections,
        if region.executable { "yes" } else { "no" },
        region.unreadable_pages,
        committed = region.committed,
    )
}

pub(super) fn push_embedded(
    target: &TargetProcess,
    image: &CapturedImage,
    report: &mut BuiltDump<'_>,
) {
    let label = embedded_label(target, image);
    save_embedded(&image.bytes, image.base, CarveSource::Image, &label, report);
}

fn save_embedded(
    bytes: &[u8],
    base: usize,
    source: CarveSource,
    label: &str,
    report: &mut BuiltDump<'_>,
) {
    let CarveResult { found, unscanned } = pe::carve_embedded(bytes, source);
    report.counts.unscanned_bytes = report.counts.unscanned_bytes.saturating_add(unscanned);

    for (index, embedded) in found.into_iter().enumerate() {
        let preferred_name = format!(
            "{label}.embed{}.{}",
            index.saturating_add(1),
            embedded.extension
        );
        let at = base.saturating_add(embedded.offset);
        let Some(bytes) = copy_range(bytes, embedded.offset, embedded.length) else {
            report.failures.push(uncopied(preferred_name, at));
            continue;
        };

        report.save(OutputFile {
            preferred_name,
            bytes,
            context: FileReport::embedded(at, embedded.kind),
        });
    }
}

fn uncopied(name: String, base: usize) -> BuildFailure {
    BuildFailure {
        name,
        base,
        error: AppError::new("the carved PE lies outside its buffer or memory ran out"),
    }
}

pub(super) fn copy_range(bytes: &[u8], offset: usize, length: usize) -> Option<Vec<u8>> {
    let slice = bytes.get(offset..offset.checked_add(length)?)?;
    let mut copy = Vec::new();
    copy.try_reserve_exact(slice.len()).ok()?;
    copy.extend_from_slice(slice);
    Some(copy)
}
