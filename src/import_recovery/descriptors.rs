use std::collections::{BTreeMap, BTreeSet};

use super::{
    ImportPlan, ImportScan, ImportSource, MAX_IMPORTS, Reference, count_until_zero, read_pointer,
    read_printable_name, read_u32, scan_import_range,
};
use crate::pe::exports::ExportIndex;
use crate::pe::{HINT_SIZE, IMPORT_DESCRIPTOR_SIZE, IMPORT_IAT_OFFSET, MAX_IMPORT_DESCRIPTORS};
use crate::pe::{ImportDescriptor, PeImage, PeKind};

const DESCRIPTOR_SCAN_STEP: usize = 4;
const MAX_ORPHAN_SCAN_THUNKS: usize = MAX_IMPORTS * 64;

pub(super) fn existing_thunk_slots(
    memory: &[u8],
    descriptors: &[u8],
    width: usize,
) -> BTreeSet<u32> {
    let mut slots = BTreeSet::new();
    for descriptor in descriptors.as_chunks::<IMPORT_DESCRIPTOR_SIZE>().0 {
        let Some(first_thunk) = read_u32(descriptor, IMPORT_IAT_OFFSET) else {
            continue;
        };

        let thunks = count_until_zero(memory, first_thunk as usize, width, MAX_IMPORTS);
        slots.extend((0..thunks).filter_map(|index| {
            first_thunk.checked_add(u32::try_from(index.checked_mul(width)?).ok()?)
        }));
    }

    slots
}

#[derive(Default)]
pub(super) struct DescriptorTable {
    pub(super) kept: Vec<u8>,
    pub(super) rejected: Vec<Rejected>,
}

pub(super) struct Rejected {
    first_thunk: u32,
    named: bool,
}

#[derive(Default)]
pub(super) struct OrphanScan {
    pub(super) tables: Vec<Vec<u8>>,
    pub(super) truncated: bool,
}

pub(super) fn rescan_rejected(
    image: &PeImage<'_>,
    observed_base: usize,
    exports: &ExportIndex,
    rejected: &[Rejected],
    referenced: &BTreeMap<u32, Reference>,
    plan: &mut ImportPlan,
) {
    let memory = image.bytes();
    let kind = image.model().kind;
    let width = kind.pointer_width();

    for descriptor in rejected.iter().filter(|descriptor| descriptor.named) {
        let start = descriptor.first_thunk as usize;
        let slots = count_until_zero(memory, start, width, MAX_IMPORTS);
        if slots == 0 {
            continue;
        }

        let scan = ImportScan {
            start,
            end: start + slots * width,
            source: ImportSource::Attested,
        };
        scan_import_range(memory, observed_base, kind, exports, scan, referenced, plan);
    }
}

pub(super) fn read_descriptors(image: &PeImage<'_>, exports: &ExportIndex) -> DescriptorTable {
    let memory = image.bytes();
    let model = image.model();
    let mut table = DescriptorTable::default();
    let mut budget = MAX_IMPORTS;

    for descriptor in image.import_descriptors() {
        let named = read_printable_name(memory, descriptor.name as usize).is_some();
        let valid =
            thunk_table_length(memory, model.kind, exports, &descriptor, &mut budget).is_some();
        if !named || !valid {
            table.rejected.push(Rejected {
                first_thunk: descriptor.iat,
                named,
            });
            continue;
        }

        table
            .kept
            .extend(descriptor.raw(memory).unwrap_or_default());
    }

    table
}

fn thunk_table_length(
    memory: &[u8],
    kind: PeKind,
    exports: &ExportIndex,
    descriptor: &ImportDescriptor,
    budget: &mut usize,
) -> Option<usize> {
    let bound = descriptor.lookup == 0; // the loader overwrote the only table
    let table = match bound {
        true => descriptor.iat,
        false => descriptor.lookup,
    } as usize;
    let width = kind.pointer_width();

    for index in 0..*budget {
        let offset = table.checked_add(index.saturating_mul(width))?;
        let value = read_pointer(memory, offset, width)?;
        *budget = budget.saturating_sub(1);

        if value == 0 {
            return (index > 0).then_some(index);
        }

        if value as u64 & kind.ordinal_flag() == 0 {
            read_printable_name(memory, value.checked_add(HINT_SIZE)?)?;
        } else if bound && exports.covers(value) {
            return None; // a resolved address in the upper half, not an ordinal
        }
    }

    None
}

pub(super) fn scan_for_orphaned_descriptors(
    image: &PeImage<'_>,
    exports: &ExportIndex,
) -> OrphanScan {
    let memory = image.bytes();
    let model = image.model();
    let mut found = OrphanScan::default();
    let mut thunks_left = MAX_ORPHAN_SCAN_THUNKS;

    for section in &model.sections {
        if !section.is_data() {
            continue;
        }

        let range = section.range_in(memory);
        let mut offset = range.start;

        while offset.saturating_add(IMPORT_DESCRIPTOR_SIZE) <= range.end {
            if thunks_left == 0 {
                found.truncated = true;
                return found;
            }

            let granted = MAX_IMPORTS.min(thunks_left);
            let mut budget = granted;
            let table = try_descriptor_array(memory, model.kind, exports, offset, &mut budget);
            thunks_left = thunks_left.saturating_sub(granted.saturating_sub(budget));

            let step = match table {
                Some(table) => {
                    let length = table.len();
                    found.tables.push(table);
                    length
                }
                None => DESCRIPTOR_SCAN_STEP,
            };
            if found.tables.len() > 1 {
                return found; // two tables already mean refusal
            }

            offset = offset.saturating_add(step);
        }
    }

    found
}

fn try_descriptor_array(
    memory: &[u8],
    kind: PeKind,
    exports: &ExportIndex,
    start: usize,
    budget: &mut usize,
) -> Option<Vec<u8>> {
    let mut descriptors = Vec::new();

    for index in 0..MAX_IMPORT_DESCRIPTORS {
        let at = start.checked_add(index.checked_mul(IMPORT_DESCRIPTOR_SIZE)?)?;
        let descriptor = ImportDescriptor::read(memory, at)?;
        let raw = descriptor.raw(memory)?;

        if raw.iter().all(|byte| *byte == 0) {
            break;
        }

        if descriptor.ends_table() {
            return None;
        }

        read_printable_name(memory, descriptor.name as usize)?;
        thunk_table_length(memory, kind, exports, &descriptor, budget)?;
        descriptors.extend_from_slice(raw);
    }

    (!descriptors.is_empty()).then_some(descriptors)
}
