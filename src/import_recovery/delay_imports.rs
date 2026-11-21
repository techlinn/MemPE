use std::collections::{BTreeMap, BTreeSet};

use super::{
    ImportPlan, ImportScan, ImportSource, MAX_IMPORTS, Reference, collect_recovered_slots,
    count_until_zero, read_pointer, read_printable_name, read_u32, resolve_value,
    scan_import_range,
};
use crate::pe::exports::ExportIndex;
use crate::pe::{DELAY_ATTRIBUTES_OFFSET, DELAY_ATTRIBUTES_RVA_BASED, DELAY_INT_OFFSET};
use crate::pe::{DELAY_DESCRIPTOR_SIZE, DELAY_IAT_OFFSET, DELAY_NAME_OFFSET};
use crate::pe::{DELAY_IMPORT_DIRECTORY, MAX_IMPORT_DESCRIPTORS, PeImage, PeKind};

pub(super) fn scan_delay_imports(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    referenced: &BTreeMap<u32, Reference>,
    plan: &mut ImportPlan,
) {
    let Some(directory) = image.directory(DELAY_IMPORT_DIRECTORY) else {
        return;
    };

    let directory_size = directory.size() as usize;
    if directory_size < DELAY_DESCRIPTOR_SIZE {
        return;
    }

    let memory = image.bytes();
    let kind = image.model().kind;
    let width = kind.pointer_width();
    let already_recovered = collect_recovered_slots(plan, width);
    let max_descriptors = (directory_size / DELAY_DESCRIPTOR_SIZE).min(MAX_IMPORT_DESCRIPTORS);
    let mut budget = MAX_IMPORTS;

    for index in 0..max_descriptors {
        let Some(offset) = directory
            .rva()
            .as_usize()
            .checked_add(index.saturating_mul(DELAY_DESCRIPTOR_SIZE))
        else {
            break;
        };

        let Some(descriptor) = memory.get(offset..offset.saturating_add(DELAY_DESCRIPTOR_SIZE))
        else {
            break;
        };

        if descriptor.iter().all(|byte| *byte == 0) {
            break;
        }

        let Some((start, end)) = delay_table_range(memory, descriptor, width, &mut budget) else {
            plan.counts.skipped_delay_descriptors =
                plan.counts.skipped_delay_descriptors.saturating_add(1);
            continue;
        };

        if u32::try_from(start).is_ok_and(|slot| already_recovered.contains(&slot)) {
            continue;
        }

        let scan = ImportScan {
            start,
            end,
            source: ImportSource::Delayed,
        };

        let unbound = unbound_delay_slots(memory, observed_base, kind, exports, &scan);
        plan.unbound_delay_slots.extend(unbound);
        scan_import_range(memory, observed_base, kind, exports, scan, referenced, plan);
    }
}

fn unbound_delay_slots(
    memory: &[u8],
    observed_base: usize,
    kind: PeKind,
    exports: &ExportIndex,
    scan: &ImportScan,
) -> BTreeSet<u32> {
    let width = kind.pointer_width();
    let mut unbound = BTreeSet::new();
    let mut offset = scan.start;

    while offset.saturating_add(width) <= scan.end {
        let Some(value) = read_pointer(memory, offset, width) else {
            break;
        };

        if resolve_value(memory, observed_base, kind, value, exports).is_err()
            && let Ok(slot) = u32::try_from(offset)
        {
            unbound.insert(slot);
        }

        offset = offset.saturating_add(width);
    }

    unbound
}

fn delay_table_range(
    memory: &[u8],
    descriptor: &[u8],
    width: usize,
    budget: &mut usize,
) -> Option<(usize, usize)> {
    // without the flag the fields are vc6-era virtual addresses
    if read_u32(descriptor, DELAY_ATTRIBUTES_OFFSET)? & DELAY_ATTRIBUTES_RVA_BASED == 0 {
        return None;
    }

    read_printable_name(memory, read_u32(descriptor, DELAY_NAME_OFFSET)? as usize)?;

    let iat_rva = read_u32(descriptor, DELAY_IAT_OFFSET)? as usize;
    let int_rva = read_u32(descriptor, DELAY_INT_OFFSET)? as usize;
    if iat_rva == 0
        || int_rva == 0
        || !iat_rva.is_multiple_of(width)
        || !int_rva.is_multiple_of(width)
    {
        return None;
    }

    let entries = delay_table_length(memory, iat_rva, width, budget)?;

    if entries == 0 || entries != delay_table_length(memory, int_rva, width, budget)? {
        return None;
    }

    let end = iat_rva.checked_add(entries.checked_mul(width)?)?;

    Some((iat_rva, end))
}

fn delay_table_length(
    memory: &[u8],
    start: usize,
    width: usize,
    budget: &mut usize,
) -> Option<usize> {
    let limit = *budget;
    let entries = count_until_zero(memory, start, width, limit);
    *budget = limit.saturating_sub(entries.saturating_add(1));

    let terminator = start.checked_add(entries.checked_mul(width)?)?;
    (entries < limit && read_pointer(memory, terminator, width)? == 0).then_some(entries)
}
