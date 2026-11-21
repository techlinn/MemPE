use std::ops::Range;

use super::tables::relocate;
use crate::pe::bytes::read_u32;
use crate::pe::parse::parse_memory_image;
use crate::pe::{DIRECTORY_COUNT, Rva, SECURITY_DIRECTORY};

pub(crate) struct FreshCopy {
    pub(crate) bytes: Vec<u8>,
    pub(crate) changed: usize,
    pub(crate) left_in_entry_section: usize,
}

// the program's sections as the packer unpacked them from the file, before its own code wrote to them
pub(crate) struct InitialData<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) base: usize,
}

pub(crate) fn with_initial_data(
    memory: &[u8],
    restored: &[u8],
    initial: InitialData<'_>,
    base: usize,
    end: usize,
    left_alone: &[Range<usize>],
) -> Option<FreshCopy> {
    let image = parse_memory_image(restored).ok()?;
    let model = image.model();
    let delta = base.wrapping_sub(initial.base);
    let mut initial = initial.bytes.get(..end.min(initial.bytes.len()))?.to_vec();

    if delta != 0 {
        relocate(&mut initial, restored, model, |value, _| {
            value.wrapping_add(delta)
        })?;
    }

    let entry = read_u32(restored, model.entry_point_offset).ok()?;
    let headers = read_u32(restored, model.size_of_headers_offset).ok()? as usize;
    let kept = (0..DIRECTORY_COUNT)
        .filter(|index| *index != SECURITY_DIRECTORY) // a file offset, not an rva
        .filter_map(|index| model.directory(restored, index))
        .map(|directory| {
            let start = directory.rva().as_usize();
            start..start.saturating_add(directory.size() as usize)
        })
        .chain(left_alone.iter().cloned())
        .collect::<Vec<_>>();

    let mut fresh = restored.to_vec();
    let mut changed = 0usize;
    let mut left_in_entry_section = 0usize;

    for section in &model.sections {
        let start = section.virtual_address().as_usize();
        let span = start..start.saturating_add(section.span() as usize);
        let holds_entry = section.contains_rva(Rva(entry)); // file code may hold the packer's jumps

        let stop = span
            .end
            .min(initial.len())
            .min(memory.len())
            .min(fresh.len());
        for at in span.start.max(headers)..stop {
            let untouched = restored[at] == memory[at];
            let resets = untouched
                && initial[at] != memory[at]
                && !kept.iter().any(|range| range.contains(&at));

            match (resets, holds_entry) {
                (false, _) => {}
                (true, true) => left_in_entry_section += 1,
                (true, false) => {
                    fresh[at] = initial[at];
                    changed += 1;
                }
            }
        }
    }

    (changed > 0).then_some(FreshCopy {
        bytes: fresh,
        changed,
        left_in_entry_section,
    })
}
