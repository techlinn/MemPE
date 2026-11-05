use std::ops::Range;

use super::FIRST_SECTION_RVA;
use super::relocations::relocate;
use crate::pe::image::read_u32;
use crate::pe::packers::FreshImage;
use crate::pe::parse::{parse_disk_image, parse_memory_image};
use crate::pe::{PeModel, Rva};

const DIRECTORY_COUNT: usize = 16;

pub(crate) fn map_disk_image(file: &[u8], end: usize) -> Option<Vec<u8>> {
    let disk = parse_disk_image(file).ok()?;
    let mut image = vec![0u8; end];

    let headers = read_u32(file, disk.model().size_of_headers_offset).ok()? as usize;
    let mapped_headers = headers.min(file.len()).min(end);
    image
        .get_mut(..mapped_headers)?
        .copy_from_slice(file.get(..mapped_headers)?);

    for section in disk.model().sections() {
        let rva = section.virtual_address().as_usize();
        let start = section.raw_pointer as usize;
        let length = (section.raw_size as usize).min(section.span() as usize);
        let raw = file.get(start..start.checked_add(length)?)?;
        if let Some(slot) = image.get_mut(rva..rva.saturating_add(raw.len())) {
            slot.copy_from_slice(raw);
        }
    }

    Some(image)
}

pub(crate) fn fresh_image(
    memory: &[u8],
    restored: &[u8],
    pristine: &[u8],
    pristine_base: usize,
    base: usize,
    end: usize,
    left_alone: &[Range<usize>],
) -> Option<FreshImage> {
    let image = parse_memory_image(restored).ok()?;
    let model = image.model();
    let mut pristine = pristine.get(..end.min(pristine.len()))?.to_vec();

    let delta = base.wrapping_sub(pristine_base);
    if delta != 0 {
        rebase(&mut pristine, restored, model, delta)?;
    }

    let entry = read_u32(restored, model.entry_point_offset).ok()?;
    let mut kept = (0..DIRECTORY_COUNT)
        .filter_map(|index| model.directory(restored, index).ok().flatten())
        .map(|directory| {
            let start = directory.rva().as_usize();
            start..start.saturating_add(directory.size() as usize)
        })
        .chain(left_alone.iter().cloned())
        .collect::<Vec<_>>(); // tables mempe rebuilt or the loader fills in stay as restored

    let mut fresh = restored.to_vec();
    let mut changed = 0usize;

    for section in model.sections() {
        let start = section.virtual_address().as_usize();
        let span = start..start.saturating_add(section.span() as usize);
        if section.contains_rva(Rva(entry)) {
            kept.push(span); // the code may carry the packer's own jumps in the file
            continue;
        }

        let stop = span
            .end
            .min(pristine.len())
            .min(memory.len())
            .min(fresh.len());
        for at in span.start.max(FIRST_SECTION_RVA)..stop {
            let untouched = restored[at] == memory[at];
            if untouched
                && pristine[at] != memory[at]
                && !kept.iter().any(|range| range.contains(&at))
            {
                fresh[at] = pristine[at];
                changed += 1;
            }
        }
    }

    (changed > 0).then_some(FreshImage {
        bytes: fresh,
        changed,
    })
}

fn rebase(bytes: &mut [u8], restored: &[u8], model: &PeModel, delta: usize) -> Option<()> {
    relocate(bytes, restored, model, |value, _| value.wrapping_add(delta))
}
